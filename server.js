const express = require('express');
const http = require('http');
const { Server } = require("socket.io");
const path = require('path');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

const PORT = process.env.PORT || 3000;

// Serve static files from the 'public' directory
app.use(express.static(path.join(__dirname, 'src', 'public')));

let users = {}; // Store user sockets and public keys
// Map userId to array of socket IDs
let userIdToSockets = {};

io.on('connection', (socket) => {
    console.log(`User connected: ${socket.id}`);

    // When a user joins with their public key
    socket.on('join', ({ username, publicKey, userId }) => {
        if (!userId) {
            console.log(`Ignored join for ${username} (${socket.id}) due to missing userId`);
            return;
        }
        // Prevent duplicate join for same socket
        if (users[socket.id] && users[socket.id].userId === userId) {
            console.log(`Duplicate join ignored for ${username} (${socket.id}) userId=${userId}`);
            return;
        }
        console.log(`User ${username} (${socket.id}) joined. userId=${userId}`);
        users[socket.id] = { username, publicKey, userId };
        if (!userIdToSockets[userId]) userIdToSockets[userId] = [];
        if (!userIdToSockets[userId].includes(socket.id)) {
            userIdToSockets[userId].push(socket.id);
        }

        // Notify other users about the new user
        socket.broadcast.emit('user joined', { id: socket.id, username, publicKey, userId });

        // Send existing users to the new user
        for (const id in users) {
            if (id !== socket.id) {
                socket.emit('user joined', { id, ...users[id] });
            }
        }
    });

    // When a user sends a secure message
    socket.on('secure message', (data) => {
        let payload = { from: socket.id, ...data };
        if (data.isGroupMessage) {
            // Attach userId from users table if not present
            if (!payload.userId && users[socket.id] && users[socket.id].userId) {
                payload.userId = users[socket.id].userId;
            }
            const senderUserId = payload.userId;
            // Send to only one socket per userId except sender
            const sentUserIds = new Set();
            for (const [sockId, user] of Object.entries(users)) {
                if (user.userId && user.userId !== senderUserId && !sentUserIds.has(user.userId)) {
                    io.to(sockId).emit('secure message', payload);
                    sentUserIds.add(user.userId);
                }
            }
            console.log(`Broadcasted group message from ${socket.id} (userId=${payload.userId}) to userIds:`, Array.from(sentUserIds));
        } else {
            // Always treat data.to as userId, never socketId
            let targetSocketId = null;
            if (data.to && userIdToSockets[data.to] && userIdToSockets[data.to].length > 0) {
                // data.to is a userId
                targetSocketId = userIdToSockets[data.to][0];
            } else if (data.to && users[data.to]) {
                // data.to is a socketId, which is incorrect usage
                console.error(`ERROR: data.to (${data.to}) is a socketId, not a userId. Client must send userId as 'to' for private messages.`);
                return;
            }
            if (targetSocketId) {
                io.to(targetSocketId).emit('secure message', payload);
                console.log(`Relaying private message from ${socket.id} to ${targetSocketId} (userId=${data.to})`);
            } else {
                console.log(`Could not find target socket for private message from ${socket.id} (userId=${data.to})`);
            }
        }
    });

    // When a user disconnects
    socket.on('disconnect', () => {
        console.log(`User disconnected: ${socket.id}`);
        const user = users[socket.id];
        if (user && user.userId && userIdToSockets[user.userId]) {
            userIdToSockets[user.userId] = userIdToSockets[user.userId].filter(id => id !== socket.id);
            if (userIdToSockets[user.userId].length === 0) {
                delete userIdToSockets[user.userId];
            }
        }
        delete users[socket.id];
        // Notify other users that this user has left
        io.emit('user left', socket.id);
    });
});

// Start the server
server.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
