import { io, type Socket } from "socket.io-client"

let socket: Socket | null = null

export function initializeSocket(username: string): Socket {
  if (socket) {
    socket.disconnect()
  }

  socket = io("http://localhost:5001", {
    autoConnect: true,
  })

  socket.on("connect", () => {
    console.log("Connected to server")
    socket?.emit("join", username)
  })

  socket.on("disconnect", () => {
    console.log("Disconnected from server")
  })

  return socket
}

export function getSocket(): Socket | null {
  return socket
}

export function disconnectSocket(): void {
  if (socket) {
    socket.disconnect()
    socket = null
  }
}
