const net = require('net');
const crypto = require('crypto');

const GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';

function buildAccept(secKey) {
  return crypto.createHash('sha1').update(secKey + GUID).digest('base64');
}

function encodeFrame(opcode, data) {
  const payload = Buffer.isBuffer(data) ? data : Buffer.from(data);
  const len = payload.length;
  let header = [];

  // FIN=1, RSV=0, opcode
  header.push(0x80 | (opcode & 0x0f));

  if (len < 126) {
    header.push(len);
  } else if (len < 65536) {
    header.push(126, (len >> 8) & 0xff, len & 0xff);
  } else {
    const hi = Math.floor(len / 2 ** 32);
    const lo = len >>> 0;
    header.push(
      127,
      0, 0, 0, 0,            
      (hi & 0xff),
      (lo >>> 24) & 0xff, (lo >>> 16) & 0xff, (lo >>> 8) & 0xff, lo & 0xff
    );
  }

  return Buffer.concat([Buffer.from(header), payload]);
}

function decodeFrame(buf) {
  let i = 0;
  const b0 = buf[i++], b1 = buf[i++];
  const fin = !!(b0 & 0x80);
  const opcode = b0 & 0x0f;
  const masked = !!(b1 & 0x80);
  let len = b1 & 0x7f;

  if (len === 126) {
    len = (buf[i++] << 8) | buf[i++];
  } else if (len === 127) {
    i += 4; 
    len = (buf[i++] << 24) | (buf[i++] << 16) | (buf[i++] << 8) | buf[i++];
  }

  let maskKey = null;
  if (masked) {
    maskKey = buf.slice(i, i + 4);
    i += 4;
  }

  const payload = buf.slice(i, i + len);
  if (masked) {
    for (let j = 0; j < payload.length; j++) {
      payload[j] ^= maskKey[j % 4];
    }
  }

  return { fin, opcode, payload };
}

const server = net.createServer((socket) => {
  let isUpgraded = false;
  let buffer = Buffer.alloc(0);

  socket.on('data', (chunk) => {
    buffer = Buffer.concat([buffer, chunk]);

    if (!isUpgraded) {
      const reqEnd = buffer.indexOf('\r\n\r\n');
      if (reqEnd === -1) return;

      const req = buffer.slice(0, reqEnd).toString();
      const headers = Object.fromEntries(req.split('\r\n').slice(1)
        .map(line => {
          const idx = line.indexOf(':');
          return [line.slice(0, idx).trim().toLowerCase(), line.slice(idx + 1).trim()];
        }));

      const key = headers['sec-websocket-key'];
      if (!key || headers['upgrade']?.toLowerCase() !== 'websocket') {
        socket.end('HTTP/1.1 400 Bad Request\r\n\r\n');
        return;
      }

      // Log the client's random key from the WebSocket handshake
      console.log(`[WebSocket] Connection established from ${socket.remoteAddress}:${socket.remotePort}`);
      console.log(`[WebSocket] Client random key (Sec-WebSocket-Key): ${key}`);
      
      const accept = buildAccept(key);
      console.log(`[WebSocket] Generated accept key (Sec-WebSocket-Accept): ${accept}`);
      socket.write(
        'HTTP/1.1 101 Switching Protocols\r\n' +
        'Upgrade: websocket\r\n' +
        'Connection: Upgrade\r\n' +
        `Sec-WebSocket-Accept: ${accept}\r\n` +
        '\r\n'
      );

      isUpgraded = true;
      buffer = buffer.subarray(reqEnd + 4); // remove HTTP headers
    }

    // Frame processing loop
    while (buffer.length >= 2) {
      const b1 = buffer[1];
      let len = b1 & 0x7f;
      let offset = 2;
      if (len === 126) {
        if (buffer.length < offset + 2) break;
        len = (buffer[offset] << 8) | buffer[offset + 1];
        offset += 2;
      } else if (len === 127) {
        if (buffer.length < offset + 8) break;
        offset += 8;
        len = (buffer[offset - 4] << 24) | (buffer[offset - 3] << 16) | (buffer[offset - 2] << 8) | buffer[offset - 1];
      }

      const masked = !!(b1 & 0x80);
      const need = offset + (masked ? 4 : 0) + len;
      if (buffer.length < need) break;

      const frameBuf = buffer.slice(0, need);
      buffer = buffer.slice(need);

      const { opcode, payload } = decodeFrame(frameBuf);

      if (opcode === 0x9) { // ping
        socket.write(encodeFrame(0xA, payload)); // pong
      } else if (opcode === 0x8) { // close
        socket.write(encodeFrame(0x8, Buffer.alloc(0)));
        socket.end();
      } else if (opcode === 0x1) { // text
        const msg = payload.toString('utf8');
        // Echo example with structured envelope
        const reply = JSON.stringify({ type: 'echo', ts: Date.now(), data: msg });
        socket.write(encodeFrame(0x1, reply));
      } else if (opcode === 0x2) { // binary
        // Process binary
        socket.write(encodeFrame(0x2, payload));
      }
    }
  });

  socket.on('error', () => {});
});

server.listen(8080);