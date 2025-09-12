"use client";

import { useState, useEffect } from "react";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Badge } from "@/components/ui/badge";
import {
  Shield,
  Send,
  Inbox,
  User,
  Key,
  Lock,
  Bell,
  Wifi,
  WifiOff,
  LogIn,
} from "lucide-react";
import { useToast } from "@/hooks/use-toast";
import { initializeSocket, disconnectSocket, getSocket } from "@/lib/socket";
import {
  generateKeyPair,
  storePrivateKey,
  getPrivateKey,
  getPublicKey,
  getUsers,
  encryptMessage,
  sendMessage,
  getMessages,
  decryptMessage,
} from "@/lib/crypto";

export default function PGPMessagingApp() {
  const [currentUser, setCurrentUser] = useState<string | null>(null);
  const [isRegistered, setIsRegistered] = useState(false);
  const [isConnected, setIsConnected] = useState(false);
  const [newMessageCount, setNewMessageCount] = useState(0);
  const [showLogin, setShowLogin] = useState(false);
  const { toast } = useToast();

  useEffect(() => {
    // Check if user is already registered
    const savedUser = localStorage.getItem("pgp-username");
    if (savedUser) {
      setCurrentUser(savedUser);
      setIsRegistered(true);

      const socket = initializeSocket(savedUser);

      socket.on("connect", () => {
        setIsConnected(true);
      });

      socket.on("disconnect", () => {
        setIsConnected(false);
      });

      socket.on("newMessage", (messageData) => {
        setNewMessageCount((prev) => prev + 1);
        toast({
          title: "New Message!",
          description: `You received a message from ${messageData.from}`,
        });
      });
    }

    return () => {
      disconnectSocket();
    };
  }, [toast]);

  if (!isRegistered) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-green-50 via-green-100 to-emerald-100 relative overflow-hidden">
        <div
          className="absolute inset-0 opacity-20"
          style={{
            backgroundImage: `url("data:image/svg+xml,%3Csvg width='60' height='60' viewBox='0 0 60 60' xmlns='http://www.w3.org/2000/svg'%3E%3Cg fill='none' fillRule='evenodd'%3E%3Cg fill='%2325D366' fillOpacity='0.1'%3E%3Ccircle cx='30' cy='30' r='2'/%3E%3C/g%3E%3C/g%3E%3C/svg%3E")`,
          }}
        ></div>
        {showLogin ? (
          <LoginPage
            onLogin={(username) => {
              setCurrentUser(username);
              setIsRegistered(true);

              const socket = initializeSocket(username);
              socket.on("connect", () => setIsConnected(true));
              socket.on("disconnect", () => setIsConnected(false));
              socket.on("newMessage", (messageData) => {
                setNewMessageCount((prev) => prev + 1);
                toast({
                  title: "New Message!",
                  description: `You received a message from ${messageData.from}`,
                });
              });
            }}
            onSwitchToRegister={() => setShowLogin(false)}
            toast={toast}
          />
        ) : (
          <RegisterPage
            onRegister={(username) => {
              setCurrentUser(username);
              setIsRegistered(true);

              const socket = initializeSocket(username);
              socket.on("connect", () => setIsConnected(true));
              socket.on("disconnect", () => setIsConnected(false));
              socket.on("newMessage", (messageData) => {
                setNewMessageCount((prev) => prev + 1);
                toast({
                  title: "New Message!",
                  description: `You received a message from ${messageData.from}`,
                });
              });
            }}
            onSwitchToLogin={() => setShowLogin(true)}
            toast={toast}
          />
        )}
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-green-50 via-green-100 to-emerald-100 relative overflow-hidden">
      <div
        className="absolute inset-0 opacity-20"
        style={{
          backgroundImage: `url("data:image/svg+xml,%3Csvg width='60' height='60' viewBox='0 0 60 60' xmlns='http://www.w3.org/2000/svg'%3E%3Cg fill='none' fillRule='evenodd'%3E%3Cg fill='%2325D366' fillOpacity='0.1'%3E%3Ccircle cx='30' cy='30' r='2'/%3E%3C/g%3E%3C/g%3E%3C/svg%3E")`,
        }}
      ></div>

      <header className="border-b border-green-200/50 bg-white/70 backdrop-blur-xl shadow-sm">
        <div className="container mx-auto px-4 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Shield className="h-6 w-6 text-green-600" />
              <h1 className="text-xl font-semibold text-gray-800">
                SecureChat
              </h1>
              <Badge
                variant={isConnected ? "default" : "secondary"}
                className={`ml-2 ${
                  isConnected
                    ? "bg-green-100 text-green-700 border-green-300"
                    : "bg-gray-100 text-gray-600 border-gray-300"
                } backdrop-blur-sm`}
              >
                {isConnected ? (
                  <div className="flex items-center gap-1">
                    <Wifi className="h-3 w-3" />
                    Online
                  </div>
                ) : (
                  <div className="flex items-center gap-1">
                    <WifiOff className="h-3 w-3" />
                    Offline
                  </div>
                )}
              </Badge>
            </div>
            <div className="flex items-center gap-2">
              <User className="h-4 w-4 text-green-600" />
              <span className="text-sm text-gray-700">{currentUser}</span>
              <Button
                variant="outline"
                size="sm"
                className="border-green-200 bg-white/80 text-gray-700 hover:bg-green-50 backdrop-blur-sm"
                onClick={() => {
                  localStorage.removeItem("pgp-username");
                  disconnectSocket();
                  setIsRegistered(false);
                  setCurrentUser(null);
                  setIsConnected(false);
                  setNewMessageCount(0);
                }}
              >
                Logout
              </Button>
            </div>
          </div>
        </div>
      </header>

      <main className="container mx-auto px-4 py-8">
        <Tabs defaultValue="inbox" className="w-full">
          <TabsList className="grid w-full grid-cols-2 bg-white/80 backdrop-blur-xl border border-green-200/50 shadow-sm">
            <TabsTrigger
              value="inbox"
              className="flex items-center gap-2 data-[state=active]:bg-green-100 data-[state=active]:text-green-800 text-gray-600"
            >
              <Inbox className="h-4 w-4" />
              Inbox
              {newMessageCount > 0 && (
                <Badge
                  variant="destructive"
                  className="ml-1 h-5 w-5 p-0 text-xs bg-red-500 text-white"
                >
                  {newMessageCount > 9 ? "9+" : newMessageCount}
                </Badge>
              )}
            </TabsTrigger>
            <TabsTrigger
              value="send"
              className="flex items-center gap-2 data-[state=active]:bg-green-100 data-[state=active]:text-green-800 text-gray-600"
            >
              <Send className="h-4 w-4" />
              Send Message
            </TabsTrigger>
          </TabsList>

          <TabsContent value="inbox">
            <InboxTab
              username={currentUser!}
              toast={toast}
              newMessageCount={newMessageCount}
              setNewMessageCount={setNewMessageCount}
            />
          </TabsContent>

          <TabsContent value="send">
            <SendMessageTab username={currentUser!} toast={toast} />
          </TabsContent>
        </Tabs>
      </main>
    </div>
  );
}

function LoginPage({
  onLogin,
  onSwitchToRegister,
  toast,
}: {
  onLogin: (username: string) => void;
  onSwitchToRegister: () => void;
  toast: any;
}) {
  const [usernameOrEmail, setUsernameOrEmail] = useState("");
  const [password, setPassword] = useState("");
  const [isLoading, setIsLoading] = useState(false);

  const handleLogin = async () => {
    if (!usernameOrEmail || !password) {
      toast({
        title: "Error",
        description: "Please fill in all fields",
        variant: "destructive",
      });
      return;
    }

    setIsLoading(true);

    try {
      const response = await fetch("http://localhost:5001/api/login", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          usernameOrEmail,
          password,
        }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || "Login failed");
      }

      // Save username to localStorage
      localStorage.setItem("pgp-username", data.username);

      toast({
        title: "Success!",
        description: "Logged in successfully",
      });

      onLogin(data.username);
    } catch (error) {
      toast({
        title: "Login Failed",
        description:
          error instanceof Error ? error.message : "Unknown error occurred",
        variant: "destructive",
      });
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center p-4 relative z-10">
      <Card className="w-full max-w-md bg-white/90 backdrop-blur-xl border border-green-200/50 shadow-xl">
        <CardHeader className="text-center">
          <div className="flex justify-center mb-4">
            <Shield className="h-12 w-12 text-green-600" />
          </div>
          <CardTitle className="text-2xl text-gray-800">Welcome Back</CardTitle>
          <CardDescription className="text-gray-600">
            Sign in to your SecureChat account
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="usernameOrEmail" className="text-gray-700">
              Username or Email
            </Label>
            <Input
              id="usernameOrEmail"
              value={usernameOrEmail}
              onChange={(e) => setUsernameOrEmail(e.target.value)}
              placeholder="Enter your username or email"
              className="bg-white/80 border-green-200 text-gray-800 placeholder:text-gray-500 backdrop-blur-sm focus:border-green-400"
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor="password" className="text-gray-700">
              Password
            </Label>
            <Input
              id="password"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Enter your password"
              onKeyDown={(e) => e.key === "Enter" && handleLogin()}
              className="bg-white/80 border-green-200 text-gray-800 placeholder:text-gray-500 backdrop-blur-sm focus:border-green-400"
            />
          </div>
          <Button
            className="w-full bg-green-600 hover:bg-green-700 text-white"
            onClick={handleLogin}
            disabled={!usernameOrEmail || !password || isLoading}
          >
            {isLoading ? (
              <div className="flex items-center gap-2">
                <LogIn className="h-4 w-4 animate-spin" />
                Signing In...
              </div>
            ) : (
              <div className="flex items-center gap-2">
                <LogIn className="h-4 w-4" />
                Sign In
              </div>
            )}
          </Button>
          <div className="text-center">
            <Button
              variant="link"
              className="text-green-600 hover:text-green-700"
              onClick={onSwitchToRegister}
            >
              Don't have an account? Register here
            </Button>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

function RegisterPage({
  onRegister,
  onSwitchToLogin,
  toast,
}: {
  onRegister: (username: string) => void;
  onSwitchToLogin: () => void;
  toast: any;
}) {
  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [passphrase, setPassphrase] = useState("");
  const [confirmPassphrase, setConfirmPassphrase] = useState("");
  const [isLoading, setIsLoading] = useState(false);

  const handleRegister = async () => {
    if (password !== confirmPassword) {
      toast({
        title: "Error",
        description: "Passwords do not match",
        variant: "destructive",
      });
      return;
    }

    if (passphrase !== confirmPassphrase) {
      toast({
        title: "Error",
        description: "Passphrases do not match",
        variant: "destructive",
      });
      return;
    }

    if (password.length < 6) {
      toast({
        title: "Error",
        description: "Password must be at least 6 characters long",
        variant: "destructive",
      });
      return;
    }

    if (passphrase.length < 8) {
      toast({
        title: "Error",
        description: "Passphrase must be at least 8 characters long",
        variant: "destructive",
      });
      return;
    }

    setIsLoading(true);

    try {
      // Generate PGP key pair
      toast({
        title: "Generating Keys",
        description: "Creating your RSA key pair...",
      });

      const keyPair = await generateKeyPair(username, passphrase);

      // Store encrypted private key locally
      await storePrivateKey(username, keyPair.privateKey, keyPair.publicKey);

      const response = await fetch("http://localhost:5001/api/register", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          username,
          email,
          password,
          passphrase,
          publicKey: keyPair.publicKey,
        }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || "Registration failed");
      }

      // Save username to localStorage
      localStorage.setItem("pgp-username", username);

      toast({
        title: "Success!",
        description: "Your account has been created and keys generated",
      });

      onRegister(username);
    } catch (error) {
      toast({
        title: "Registration Failed",
        description:
          error instanceof Error ? error.message : "Unknown error occurred",
        variant: "destructive",
      });
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center p-4 relative z-10">
      <Card className="w-full max-w-md bg-white/90 backdrop-blur-xl border border-green-200/50 shadow-xl">
        <CardHeader className="text-center">
          <div className="flex justify-center mb-4">
            <Shield className="h-12 w-12 text-green-600" />
          </div>
          <CardTitle className="text-2xl text-gray-800">
            Welcome to SecureChat
          </CardTitle>
          <CardDescription className="text-gray-600">
            Create your account to start sending encrypted messages
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="username" className="text-gray-700">
              Username
            </Label>
            <Input
              id="username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="Enter your username"
              className="bg-white/80 border-green-200 text-gray-800 placeholder:text-gray-500 backdrop-blur-sm focus:border-green-400"
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor="email" className="text-gray-700">
              Email
            </Label>
            <Input
              id="email"
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="Enter your email"
              className="bg-white/80 border-green-200 text-gray-800 placeholder:text-gray-500 backdrop-blur-sm focus:border-green-400"
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor="password" className="text-gray-700">
              Password
            </Label>
            <Input
              id="password"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Enter your password"
              className="bg-white/80 border-green-200 text-gray-800 placeholder:text-gray-500 backdrop-blur-sm focus:border-green-400"
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor="confirm-password" className="text-gray-700">
              Confirm Password
            </Label>
            <Input
              id="confirm-password"
              type="password"
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              placeholder="Confirm your password"
              className="bg-white/80 border-green-200 text-gray-800 placeholder:text-gray-500 backdrop-blur-sm focus:border-green-400"
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor="passphrase" className="text-gray-700">
              Passphrase (for encryption)
            </Label>
            <Input
              id="passphrase"
              type="password"
              value={passphrase}
              onChange={(e) => setPassphrase(e.target.value)}
              placeholder="Enter a strong passphrase"
              className="bg-white/80 border-green-200 text-gray-800 placeholder:text-gray-500 backdrop-blur-sm focus:border-green-400"
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor="confirm-passphrase" className="text-gray-700">
              Confirm Passphrase
            </Label>
            <Input
              id="confirm-passphrase"
              type="password"
              value={confirmPassphrase}
              onChange={(e) => setConfirmPassphrase(e.target.value)}
              placeholder="Confirm your passphrase"
              className="bg-white/80 border-green-200 text-gray-800 placeholder:text-gray-500 backdrop-blur-sm focus:border-green-400"
            />
          </div>
          <Button
            className="w-full bg-green-600 hover:bg-green-700 text-white"
            onClick={handleRegister}
            disabled={
              !username ||
              !email ||
              !password ||
              !confirmPassword ||
              !passphrase ||
              !confirmPassphrase ||
              isLoading
            }
          >
            {isLoading ? (
              <div className="flex items-center gap-2">
                <Key className="h-4 w-4 animate-spin" />
                Creating Account...
              </div>
            ) : (
              <div className="flex items-center gap-2">
                <Lock className="h-4 w-4" />
                Create Account & Generate Keys
              </div>
            )}
          </Button>
          <div className="text-center">
            <Button
              variant="link"
              className="text-green-600 hover:text-green-700"
              onClick={onSwitchToLogin}
            >
              Already have an account? Sign in here
            </Button>
          </div>
          <div className="text-xs text-gray-600 text-center space-y-1">
            <p>Your private key will be encrypted and stored locally.</p>
            <p>Only your public key will be shared with the server.</p>
            <p>Use a strong passphrase - you'll need it to decrypt messages.</p>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

// function InboxTab({
//   username,
//   toast,
//   newMessageCount,
//   setNewMessageCount,
// }: {
//   username: string;
//   toast: any;
//   newMessageCount: number;
//   setNewMessageCount: (count: number) => void;
// }) {
//   const [messages, setMessages] = useState<any[]>([]);
//   const [isLoading, setIsLoading] = useState(true);
//   const [passphrase, setPassphrase] = useState("");
//   const [showPassphraseDialog, setShowPassphraseDialog] = useState(false);
//   const [selectedMessage, setSelectedMessage] = useState<any>(null);

//   useEffect(() => {
//     loadMessages();

//     const socket = getSocket();
//     if (socket) {
//       socket.on("newMessage", (messageData) => {
//         // Add new message to the list
//         setMessages((prev) => [messageData, ...prev]);
//       });
//     }

//     if (newMessageCount > 0) {
//       setNewMessageCount(0);
//     }

//     return () => {
//       const socket = getSocket();
//       if (socket) {
//         socket.off("newMessage");
//       }
//     };
//   }, [newMessageCount, setNewMessageCount]);

//   const loadMessages = async () => {
//     try {
//       const fetchedMessages = await getMessages(username);
//       setMessages(fetchedMessages);
//     } catch (error) {
//       toast({
//         title: "Error",
//         description: "Failed to load messages",
//         variant: "destructive",
//       });
//     } finally {
//       setIsLoading(false);
//     }
//   };

//   const decryptSelectedMessage = async () => {
//     if (!selectedMessage || !passphrase) return;

//     try {
//       const privateKey = await getPrivateKey(username);
//       if (!privateKey) {
//         throw new Error("Private key not found");
//       }

//       console.log("[v0] Attempting to decrypt message:", selectedMessage);
//       console.log("[v0] Using passphrase length:", passphrase.length);

//       const decryptedText = await decryptMessage(
//         {
//           ciphertext: selectedMessage.ciphertext,
//           wrappedKey: selectedMessage.wrappedKey,
//           iv: selectedMessage.iv,
//         },
//         privateKey,
//         passphrase
//       );

//       console.log("[v0] Decryption successful");

//       // Update message with decrypted text
//       setMessages((prev) =>
//         prev.map((msg) =>
//           msg._id === selectedMessage._id || msg.id === selectedMessage.id
//             ? { ...msg, decryptedText }
//             : msg
//         )
//       );

//       setShowPassphraseDialog(false);
//       setPassphrase("");
//       setSelectedMessage(null);

//       toast({
//         title: "Success",
//         description: "Message decrypted successfully",
//       });
//     } catch (error) {
//       console.log("[v0] Decryption error:", error);
//       toast({
//         title: "Decryption Failed",
//         description: "Invalid passphrase or corrupted message",
//         variant: "destructive",
//       });
//     }
//   };

//   if (isLoading) {
//     return (
//       <Card className="bg-white/90 backdrop-blur-xl border border-green-200/50 shadow-sm">
//         <CardContent className="flex items-center justify-center py-8">
//           <div className="text-center">
//             <Inbox className="h-8 w-8 mx-auto mb-2 animate-pulse text-green-600" />
//             <p className="text-gray-700">Loading messages...</p>
//           </div>
//         </CardContent>
//       </Card>
//     );
//   }

//   return (
//     <div className="space-y-4">
//       <Card className="bg-white/90 backdrop-blur-xl border border-green-200/50 shadow-sm">
//         <CardHeader>
//           <CardTitle className="flex items-center gap-2 text-gray-800">
//             <Inbox className="h-5 w-5 text-green-600" />
//             Your Messages ({messages.length})
//             <Badge
//               variant="outline"
//               className="ml-auto bg-green-100 text-green-700 border-green-300"
//             >
//               <Bell className="h-3 w-3 mr-1" />
//               Real-time
//             </Badge>
//           </CardTitle>
//           <CardDescription className="text-gray-600">
//             Encrypted messages sent to you • Updates automatically
//           </CardDescription>
//         </CardHeader>
//         <CardContent>
//           {messages.length === 0 ? (
//             <div className="text-center text-gray-500 py-8">
//               <Inbox className="h-12 w-12 mx-auto mb-4 opacity-50 text-green-600" />
//               <p>No messages yet</p>
//               <p className="text-sm">Messages will appear here when received</p>
//             </div>
//           ) : (
//             <div className="space-y-3">
//               {messages.map((message) => (
//                 <div
//                   key={message._id || message.id}
//                   className="border border-green-200/50 rounded-lg p-4 bg-white/60 backdrop-blur-sm shadow-sm"
//                 >
//                   <div className="flex items-center justify-between mb-2">
//                     <div className="flex items-center gap-2">
//                       <User className="h-4 w-4 text-green-600" />
//                       <span className="font-medium text-gray-800">
//                         From: {message.from}
//                       </span>
//                       {!message.decryptedText && (
//                         <Badge
//                           variant="secondary"
//                           className="text-xs bg-green-100 text-green-700 border-green-300"
//                         >
//                           New
//                         </Badge>
//                       )}
//                     </div>
//                     <span className="text-xs text-gray-500">
//                       {new Date(message.timestamp).toLocaleString()}
//                     </span>
//                   </div>
//                   {message.decryptedText ? (
//                     <div className="bg-green-50 p-3 rounded border border-green-200/50">
//                       <p className="text-gray-800">{message.decryptedText}</p>
//                     </div>
//                   ) : (
//                     <div className="space-y-2">
//                       <p className="text-sm text-gray-500">Encrypted message</p>
//                       <Button
//                         size="sm"
//                         className="bg-green-600 hover:bg-green-700 text-white"
//                         onClick={() => {
//                           setSelectedMessage(message);
//                           setShowPassphraseDialog(true);
//                         }}
//                       >
//                         <Lock className="h-4 w-4 mr-2" />
//                         Decrypt Message
//                       </Button>
//                     </div>
//                   )}
//                 </div>
//               ))}
//             </div>
//           )}
//         </CardContent>
//       </Card>

//       {showPassphraseDialog && (
//         <Card className="bg-white/90 backdrop-blur-xl border border-green-200/50 shadow-sm">
//           <CardHeader>
//             <CardTitle className="flex items-center gap-2 text-gray-800">
//               <Lock className="h-5 w-5 text-green-600" />
//               Enter Passphrase
//             </CardTitle>
//             <CardDescription className="text-gray-600">
//               Enter your passphrase to decrypt the message from{" "}
//               {selectedMessage?.from}
//             </CardDescription>
//           </CardHeader>
//           <CardContent className="space-y-4">
//             <div className="space-y-2">
//               <Label htmlFor="decrypt-passphrase" className="text-gray-700">
//                 Passphrase
//               </Label>
//               <Input
//                 id="decrypt-passphrase"
//                 type="password"
//                 value={passphrase}
//                 onChange={(e) => setPassphrase(e.target.value)}
//                 placeholder="Enter your passphrase"
//                 onKeyDown={(e) => e.key === "Enter" && decryptSelectedMessage()}
//                 autoFocus
//                 className="bg-white/80 border-green-200 text-gray-800 placeholder:text-gray-500 backdrop-blur-sm focus:border-green-400"
//               />
//             </div>
//             <div className="flex gap-2">
//               <Button
//                 onClick={decryptSelectedMessage}
//                 disabled={!passphrase}
//                 className="bg-green-600 hover:bg-green-700 text-white"
//               >
//                 <Key className="h-4 w-4 mr-2" />
//                 Decrypt
//               </Button>
//               <Button
//                 variant="outline"
//                 className="border-green-200 bg-white/80 text-gray-700 hover:bg-green-50"
//                 onClick={() => {
//                   setShowPassphraseDialog(false);
//                   setPassphrase("");
//                   setSelectedMessage(null);
//                 }}
//               >
//                 Cancel
//               </Button>
//             </div>
//           </CardContent>
//         </Card>
//       )}
//     </div>
//   );
// }

function InboxTab({
  username,
  toast,
  newMessageCount,
  setNewMessageCount,
}: {
  username: string;
  toast: any;
  newMessageCount: number;
  setNewMessageCount: (count: number) => void;
}) {
  const [messages, setMessages] = useState<any[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [passphrase, setPassphrase] = useState("");
  const [showPassphraseDialog, setShowPassphraseDialog] = useState(false);
  const [selectedMessage, setSelectedMessage] = useState<any>(null);

  // normalize messages to always have a stable id
  const normalizeMessage = (msg: any) => ({
    ...msg,
    id: msg._id || msg.id,
  });

  useEffect(() => {
    loadMessages();

    const socket = getSocket();
    if (socket) {
      socket.on("newMessage", (messageData) => {
        setMessages((prev) => [normalizeMessage(messageData), ...prev]);
      });
    }

    if (newMessageCount > 0) {
      setNewMessageCount(0);
    }

    return () => {
      const socket = getSocket();
      if (socket) {
        socket.off("newMessage");
      }
    };
  }, [newMessageCount, setNewMessageCount]);

  const loadMessages = async () => {
    try {
      const fetchedMessages = await getMessages(username);
      setMessages(fetchedMessages.map(normalizeMessage));
    } catch (error) {
      toast({
        title: "Error",
        description: "Failed to load messages",
        variant: "destructive",
      });
    } finally {
      setIsLoading(false);
    }
  };

  const decryptSelectedMessage = async () => {
    if (!selectedMessage || !passphrase) return;

    try {
      const privateKey = await getPrivateKey(username);
      if (!privateKey) {
        throw new Error("Private key not found");
      }

      console.log("[v0] Attempting to decrypt message:", selectedMessage);
      console.log("[v0] Using passphrase length:", passphrase.length);

      const decryptedText = await decryptMessage(
        {
          ciphertext: selectedMessage.ciphertext,
          wrappedKey: selectedMessage.wrappedKey,
          iv: selectedMessage.iv,
        },
        privateKey,
        passphrase
      );

      console.log("[v0] Decryption successful");

      // update only the correct message by id
      setMessages((prev) =>
        prev.map((msg) =>
          msg.id === selectedMessage.id ? { ...msg, decryptedText } : msg
        )
      );

      setShowPassphraseDialog(false);
      setPassphrase("");
      setSelectedMessage(null);

      toast({
        title: "Success",
        description: "Message decrypted successfully",
      });
    } catch (error) {
      console.log("[v0] Decryption error:", error);
      toast({
        title: "Decryption Failed",
        description: "Invalid passphrase or corrupted message",
        variant: "destructive",
      });
    }
  };

  if (isLoading) {
    return (
      <Card className="bg-white/90 backdrop-blur-xl border border-green-200/50 shadow-sm">
        <CardContent className="flex items-center justify-center py-8">
          <div className="text-center">
            <Inbox className="h-8 w-8 mx-auto mb-2 animate-pulse text-green-600" />
            <p className="text-gray-700">Loading messages...</p>
          </div>
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="space-y-4">
      <Card className="bg-white/90 backdrop-blur-xl border border-green-200/50 shadow-sm">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-gray-800">
            <Inbox className="h-5 w-5 text-green-600" />
            Your Messages ({messages.length})
            <Badge
              variant="outline"
              className="ml-auto bg-green-100 text-green-700 border-green-300"
            >
              <Bell className="h-3 w-3 mr-1" />
              Real-time
            </Badge>
          </CardTitle>
          <CardDescription className="text-gray-600">
            Encrypted messages sent to you • Updates automatically
          </CardDescription>
        </CardHeader>
        <CardContent>
          {messages.length === 0 ? (
            <div className="text-center text-gray-500 py-8">
              <Inbox className="h-12 w-12 mx-auto mb-4 opacity-50 text-green-600" />
              <p>No messages yet</p>
              <p className="text-sm">Messages will appear here when received</p>
            </div>
          ) : (
            <div className="space-y-3">
              {messages.map((message) => (
                <div
                  key={message.id}
                  className="border border-green-200/50 rounded-lg p-4 bg-white/60 backdrop-blur-sm shadow-sm"
                >
                  <div className="flex items-center justify-between mb-2">
                    <div className="flex items-center gap-2">
                      <User className="h-4 w-4 text-green-600" />
                      <span className="font-medium text-gray-800">
                        From: {message.from}
                      </span>
                      {!message.decryptedText && (
                        <Badge
                          variant="secondary"
                          className="text-xs bg-green-100 text-green-700 border-green-300"
                        >
                          New
                        </Badge>
                      )}
                    </div>
                    <span className="text-xs text-gray-500">
                      {new Date(message.timestamp).toLocaleString()}
                    </span>
                  </div>
                  {message.decryptedText ? (
                    <div className="bg-green-50 p-3 rounded border border-green-200/50">
                      <p className="text-gray-800">{message.decryptedText}</p>
                    </div>
                  ) : (
                    <div className="space-y-2">
                      <p className="text-sm text-gray-500">Encrypted message</p>
                      <Button
                        size="sm"
                        className="bg-green-600 hover:bg-green-700 text-white"
                        onClick={() => {
                          setSelectedMessage(message);
                          setShowPassphraseDialog(true);
                        }}
                      >
                        <Lock className="h-4 w-4 mr-2" />
                        Decrypt Message
                      </Button>
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      {showPassphraseDialog && (
        <Card className="bg-white/90 backdrop-blur-xl border border-green-200/50 shadow-sm">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-gray-800">
              <Lock className="h-5 w-5 text-green-600" />
              Enter Passphrase
            </CardTitle>
            <CardDescription className="text-gray-600">
              Enter your passphrase to decrypt the message from{" "}
              {selectedMessage?.from}
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="decrypt-passphrase" className="text-gray-700">
                Passphrase
              </Label>
              <Input
                id="decrypt-passphrase"
                type="password"
                value={passphrase}
                onChange={(e) => setPassphrase(e.target.value)}
                placeholder="Enter your passphrase"
                onKeyDown={(e) => e.key === "Enter" && decryptSelectedMessage()}
                autoFocus
                className="bg-white/80 border-green-200 text-gray-800 placeholder:text-gray-500 backdrop-blur-sm focus:border-green-400"
              />
            </div>
            <div className="flex gap-2">
              <Button
                onClick={decryptSelectedMessage}
                disabled={!passphrase}
                className="bg-green-600 hover:bg-green-700 text-white"
              >
                <Key className="h-4 w-4 mr-2" />
                Decrypt
              </Button>
              <Button
                variant="outline"
                className="border-green-200 bg-white/80 text-gray-700 hover:bg-green-50"
                onClick={() => {
                  setShowPassphraseDialog(false);
                  setPassphrase("");
                  setSelectedMessage(null);
                }}
              >
                Cancel
              </Button>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

function SendMessageTab({ username, toast }: { username: string; toast: any }) {
  const [recipient, setRecipient] = useState("");
  const [message, setMessage] = useState("");
  const [users, setUsers] = useState<string[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [isSending, setIsSending] = useState(false);

  useEffect(() => {
    loadUsers();
  }, []);

  const loadUsers = async () => {
    try {
      setIsLoading(true);
      const fetchedUsers = await getUsers();
      // Filter out current user
      setUsers(fetchedUsers.filter((user) => user !== username));
    } catch (error) {
      toast({
        title: "Error",
        description: "Failed to load users",
        variant: "destructive",
      });
    } finally {
      setIsLoading(false);
    }
  };

  const handleSendMessage = async () => {
    if (!recipient || !message) return;

    setIsSending(true);

    try {
      // Get recipient's public key
      const recipientPublicKey = await getPublicKey(recipient);

      // Encrypt message
      const encryptedMessage = await encryptMessage(
        message,
        recipientPublicKey
      );

      // Send to server
      await sendMessage(username, recipient, encryptedMessage);

      toast({
        title: "Message Sent!",
        description: `Your encrypted message was sent to ${recipient}`,
      });

      // Clear form
      setMessage("");
      setRecipient("");
    } catch (error) {
      toast({
        title: "Send Failed",
        description:
          error instanceof Error ? error.message : "Failed to send message",
        variant: "destructive",
      });
    } finally {
      setIsSending(false);
    }
  };

  return (
    <Card className="bg-white/90 backdrop-blur-xl border border-green-200/50 shadow-sm">
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-gray-800">
          <Send className="h-5 w-5 text-green-600" />
          Send Encrypted Message
          <Badge
            variant="outline"
            className="ml-auto bg-green-100 text-green-700 border-green-300"
          >
            <Bell className="h-3 w-3 mr-1" />
            Instant Delivery
          </Badge>
        </CardTitle>
        <CardDescription className="text-gray-600">
          Send a secure, end-to-end encrypted message • Delivered in real-time
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="space-y-2">
          <Label htmlFor="recipient" className="text-gray-700">
            Recipient
          </Label>
          {isLoading ? (
            <Input
              disabled
              placeholder="Loading users..."
              className="bg-white/80 border-green-200 text-gray-800 placeholder:text-gray-500"
            />
          ) : (
            <select
              className="flex h-10 w-full rounded-md border border-green-200 bg-white/80 backdrop-blur-sm px-3 py-2 text-sm text-gray-800 ring-offset-background file:border-0 file:bg-transparent file:text-sm file:font-medium placeholder:text-gray-500 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-green-400 focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50"
              value={recipient}
              onChange={(e) => setRecipient(e.target.value)}
            >
              <option value="" className="bg-white text-gray-800">
                Select a recipient
              </option>
              {users.map((user) => (
                <option
                  key={user}
                  value={user}
                  className="bg-white text-gray-800"
                >
                  {user}
                </option>
              ))}
            </select>
          )}
        </div>
        <div className="space-y-2">
          <Label htmlFor="message" className="text-gray-700">
            Message
          </Label>
          <Textarea
            id="message"
            value={message}
            onChange={(e) => setMessage(e.target.value)}
            placeholder="Type your message here..."
            rows={4}
            className="bg-white/80 border-green-200 text-gray-800 placeholder:text-gray-500 backdrop-blur-sm resize-none focus:border-green-400"
          />
        </div>
        <Button
          className="w-full bg-green-600 hover:bg-green-700 text-white"
          disabled={!recipient || !message || isSending}
          onClick={handleSendMessage}
        >
          {isSending ? (
            <div className="flex items-center gap-2">
              <Lock className="h-4 w-4 animate-spin" />
              Encrypting & Sending...
            </div>
          ) : (
            <div className="flex items-center gap-2">
              <Send className="h-4 w-4" />
              Send Encrypted Message
            </div>
          )}
        </Button>
        {users.length === 0 && !isLoading && (
          <p className="text-sm text-gray-500 text-center">
            No other users registered yet. Ask someone to register first!
          </p>
        )}
      </CardContent>
    </Card>
  );
}
