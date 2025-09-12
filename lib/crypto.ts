import * as openpgp from "openpgp"
import { openDB, type DBSchema, type IDBPDatabase } from "idb"

export interface KeyPair {
  publicKey: string
  privateKey: string
}

export interface EncryptedMessage {
  ciphertext: string
  wrappedKey: string
  iv: string
}

// IndexedDB schema for storing encrypted private keys
interface KeyStoreDB extends DBSchema {
  keys: {
    key: string
    value: {
      username: string
      encryptedPrivateKey: string
      publicKey: string
      createdAt: Date
    }
  }
}

// Initialize IndexedDB for key storage
async function getKeyStore(): Promise<IDBPDatabase<KeyStoreDB>> {
  return openDB<KeyStoreDB>("pgp-keystore", 1, {
    upgrade(db) {
      db.createObjectStore("keys", { keyPath: "username" })
    },
  })
}

// Generate RSA key pair using OpenPGP.js
export async function generateKeyPair(username: string, passphrase: string): Promise<KeyPair> {
  try {
    const { privateKey, publicKey } = await openpgp.generateKey({
      type: "rsa",
      rsaBits: 2048,
      userIDs: [{ name: username, email: `${username}@securechat.local` }],
      passphrase: passphrase,
    })

    return {
      publicKey: publicKey,
      privateKey: privateKey,
    }
  } catch (error) {
    throw new Error(`Failed to generate key pair: ${error}`)
  }
}

// Store encrypted private key in IndexedDB
export async function storePrivateKey(username: string, privateKey: string, publicKey: string): Promise<void> {
  try {
    const db = await getKeyStore()
    await db.put("keys", {
      username,
      encryptedPrivateKey: privateKey,
      publicKey,
      createdAt: new Date(),
    })
  } catch (error) {
    throw new Error(`Failed to store private key: ${error}`)
  }
}

// Retrieve encrypted private key from IndexedDB
export async function getPrivateKey(username: string): Promise<string | null> {
  try {
    const db = await getKeyStore()
    const keyData = await db.get("keys", username)
    return keyData?.encryptedPrivateKey || null
  } catch (error) {
    console.error("Failed to retrieve private key:", error)
    return null
  }
}

// Generate random AES key for message encryption
async function generateAESKey(): Promise<CryptoKey> {
  return await crypto.subtle.generateKey(
    {
      name: "AES-GCM",
      length: 256,
    },
    true,
    ["encrypt", "decrypt"],
  )
}

// Export AES key to raw bytes
async function exportAESKey(key: CryptoKey): Promise<ArrayBuffer> {
  return await crypto.subtle.exportKey("raw", key)
}

// Import AES key from raw bytes
async function importAESKey(keyData: ArrayBuffer): Promise<CryptoKey> {
  return await crypto.subtle.importKey(
    "raw",
    keyData,
    {
      name: "AES-GCM",
      length: 256,
    },
    true,
    ["encrypt", "decrypt"],
  )
}

// Encrypt message using hybrid cryptography (AES + RSA)
export async function encryptMessage(message: string, recipientPublicKey: string): Promise<EncryptedMessage> {
  try {
    // Generate random AES key
    const aesKey = await generateAESKey()
    const aesKeyBytes = await exportAESKey(aesKey)

    // Generate random IV for AES encryption
    const iv = crypto.getRandomValues(new Uint8Array(12))

    // Encrypt message with AES
    const messageBytes = new TextEncoder().encode(message)
    const encryptedMessage = await crypto.subtle.encrypt(
      {
        name: "AES-GCM",
        iv: iv,
      },
      aesKey,
      messageBytes,
    )

    // Encrypt AES key with recipient's RSA public key
    const publicKey = await openpgp.readKey({ armoredKey: recipientPublicKey })
    const encryptedAESKey = await openpgp.encrypt({
      message: await openpgp.createMessage({ binary: new Uint8Array(aesKeyBytes) }),
      encryptionKeys: publicKey,
    })

    return {
      ciphertext: arrayBufferToBase64(encryptedMessage),
      wrappedKey: encryptedAESKey,
      iv: arrayBufferToBase64(iv),
    }
  } catch (error) {
    throw new Error(`Failed to encrypt message: ${error}`)
  }
}

// Decrypt message using hybrid cryptography
export async function decryptMessage(
  encryptedMessage: EncryptedMessage,
  privateKeyArmored: string,
  passphrase: string,
): Promise<string> {
  try {
    console.log("[v0] Starting decryption process")

    // Read and decrypt private key
    const privateKey = await openpgp.decryptKey({
      privateKey: await openpgp.readPrivateKey({ armoredKey: privateKeyArmored }),
      passphrase: passphrase,
    })

    console.log("[v0] Private key decrypted successfully")

    // Decrypt AES key with RSA private key
    const encryptedAESKeyMessage = await openpgp.readMessage({ armoredMessage: encryptedMessage.wrappedKey })
    const { data: decryptedAESKeyBytes } = await openpgp.decrypt({
      message: encryptedAESKeyMessage,
      decryptionKeys: privateKey,
      format: "binary",
    })

    console.log("[v0] AES key decrypted successfully")

    let aesKeyBuffer: ArrayBuffer
    if (typeof decryptedAESKeyBytes === "string") {
      // Convert binary string to Uint8Array
      const keyBytes = new Uint8Array(decryptedAESKeyBytes.length)
      for (let i = 0; i < decryptedAESKeyBytes.length; i++) {
        keyBytes[i] = decryptedAESKeyBytes.charCodeAt(i)
      }

      if (keyBytes.length !== 32) {
        throw new Error(`Invalid AES key length: ${keyBytes.length} bytes, expected 32 bytes`)
      }

      aesKeyBuffer = keyBytes.buffer.slice(keyBytes.byteOffset, keyBytes.byteOffset + keyBytes.byteLength)
    } else if (decryptedAESKeyBytes instanceof Uint8Array) {
      // Ensure we have exactly 32 bytes (256 bits) for AES-256
      if (decryptedAESKeyBytes.length !== 32) {
        throw new Error(`Invalid AES key length: ${decryptedAESKeyBytes.length} bytes, expected 32 bytes`)
      }
      aesKeyBuffer = decryptedAESKeyBytes.buffer.slice(
        decryptedAESKeyBytes.byteOffset,
        decryptedAESKeyBytes.byteOffset + decryptedAESKeyBytes.byteLength,
      )
    } else if (decryptedAESKeyBytes instanceof ArrayBuffer) {
      if (decryptedAESKeyBytes.byteLength !== 32) {
        throw new Error(`Invalid AES key length: ${decryptedAESKeyBytes.byteLength} bytes, expected 32 bytes`)
      }
      aesKeyBuffer = decryptedAESKeyBytes
    } else {
      throw new Error(`Unexpected AES key data type: ${typeof decryptedAESKeyBytes}`)
    }

    console.log("[v0] AES key buffer length:", aesKeyBuffer.byteLength)

    // Import decrypted AES key
    const aesKey = await importAESKey(aesKeyBuffer)

    console.log("[v0] AES key imported successfully")

    // Decrypt message with AES key
    const iv = base64ToArrayBuffer(encryptedMessage.iv)
    const ciphertext = base64ToArrayBuffer(encryptedMessage.ciphertext)

    const decryptedMessage = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: new Uint8Array(iv),
      },
      aesKey,
      ciphertext,
    )

    console.log("[v0] Message decrypted successfully")

    return new TextDecoder().decode(decryptedMessage)
  } catch (error) {
    console.log("[v0] Decryption error details:", error)
    throw new Error(`Failed to decrypt message: ${error}`)
  }
}

// Utility functions for base64 encoding/decoding
function arrayBufferToBase64(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer)
  let binary = ""
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i])
  }
  return btoa(binary)
}

function base64ToArrayBuffer(base64: string): ArrayBuffer {
  const binary = atob(base64)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i)
  }
  return bytes.buffer
}

// Register user with server
export async function registerUser(username: string, publicKey: string): Promise<void> {
  const response = await fetch("http://localhost:5001/api/register", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ username, publicKey }),
  })

  if (!response.ok) {
    const error = await response.json()
    throw new Error(error.error || "Registration failed")
  }
}

// Get user's public key from server
export async function getPublicKey(username: string): Promise<string> {
  const response = await fetch(`http://localhost:5001/api/publicKey/${username}`)

  if (!response.ok) {
    const error = await response.json()
    throw new Error(error.error || "Failed to get public key")
  }

  const data = await response.json()
  return data.publicKey
}

// Get list of users from server
export async function getUsers(): Promise<string[]> {
  const response = await fetch("http://localhost:5001/api/users")

  if (!response.ok) {
    throw new Error("Failed to get users")
  }

  const users = await response.json()
  return users.map((user: any) => user.username)
}

// Send encrypted message to server
export async function sendMessage(from: string, to: string, encryptedMessage: EncryptedMessage): Promise<void> {
  const response = await fetch("http://localhost:5001/api/messages", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      from,
      to,
      wrappedKey: encryptedMessage.wrappedKey,
      ciphertext: encryptedMessage.ciphertext,
      iv: encryptedMessage.iv,
    }),
  })

  if (!response.ok) {
    const error = await response.json()
    throw new Error(error.error || "Failed to send message")
  }
}

// Get messages for user from server
export async function getMessages(username: string): Promise<any[]> {
  const response = await fetch(`http://localhost:5001/api/messages/${username}`)

  if (!response.ok) {
    throw new Error("Failed to get messages")
  }

  return await response.json()
}
