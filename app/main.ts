import * as dgram from "dgram";

const udpSocket = dgram.createSocket("udp4");
udpSocket.bind(2053, "127.0.0.1");

// Domain to IP mapping (simple in-memory storage)
const dnsRecords: Record<string, string[]> = {
    'google.com.': ['142.250.190.78', '142.250.190.110'], // Google's IPs
    'www.google.com.': ['142.250.190.100'] // Example subdomain
};

// Helper function to parse domain name
function parseName(buffer: Buffer, offset: number): { name: string; newOffset: number } {
    let name = "";
    let originalOffset = offset;
    let jumped = false;
    let newOffset = 0;

    while (true) {
        if (offset >= buffer.length) break;

        const len = buffer.readUInt8(offset);
        offset++;

        if (len === 0) break; // End of name

        // Handle DNS compression pointers
        if ((len & 0xc0) === 0xc0) {
            if (!jumped) {
                newOffset = offset + 1;
                jumped = true;
            }
            offset = ((len & 0x3f) << 8) | buffer.readUInt8(offset);
            continue;
        }

        name += buffer.toString('ascii', offset, offset + len) + '.';
        offset += len;
    }

    if (!jumped) {
        newOffset = offset;
    }

    return { name: name, newOffset };
}

// Helper to encode domain name into DNS format
function encodeName(domain: string): Buffer {
    const parts = domain.split('.');
    const buf = Buffer.alloc(domain.length + 2); // +2 for length bytes and null terminator
    
    let offset = 0;
    for (const part of parts) {
        buf.writeUInt8(part.length, offset++);
        buf.write(part, offset, part.length, 'ascii');
        offset += part.length;
    }
    buf.writeUInt8(0, offset); // Null terminator
    
    return buf.slice(0, offset + 1);
}

udpSocket.on("message", (data: Buffer, remoteAddr: dgram.RemoteInfo) => {
    try {
        // Parse the query
        const transactionId = data.readUInt16BE(0);
        const flags = data.readUInt16BE(2);
        const questions = data.readUInt16BE(4);
        
        // Parse question section
        let offset = 12;
        const { name: queryName, newOffset } = parseName(data, offset);
        offset = newOffset;
        const qtype = data.readUInt16BE(offset);
        offset += 2;
        const qclass = data.readUInt16BE(offset);
        offset += 2;

        console.log(`Query for: ${queryName}, type: ${qtype}, class: ${qclass}`);

        // Prepare response buffer
        const response = Buffer.alloc(512); // Standard DNS UDP size
        let respOffset = 0;

        // Write header
        response.writeUInt16BE(transactionId, respOffset); // Transaction ID
        respOffset += 2;
        
        // Flags: QR=1, Opcode=0, AA=0, TC=0, RD=0, RA=0, Z=0, RCODE=0
        response.writeUInt16BE(0x8180, respOffset); // Standard response flags
        respOffset += 2;
        
        response.writeUInt16BE(questions, respOffset); // QDCOUNT
        respOffset += 2;
        
        // ANCOUNT - number of answers (check if we have records)
        const answers = dnsRecords[queryName]?.length || 0;
        response.writeUInt16BE(answers, respOffset);
        respOffset += 2;
        
        response.writeUInt16BE(0, respOffset); // NSCOUNT
        respOffset += 2;
        response.writeUInt16BE(0, respOffset); // ARCOUNT
        respOffset += 2;

        // Write question section (copy from query)
        data.copy(response, respOffset, 12, offset);
        respOffset += (offset - 12);

        // Write answer section if we have records
        if (answers > 0 && qtype === 1) { // Only handle A records (type 1)
            const namePtr = 0xc00c; // Pointer to name in question section
            
            for (const ip of dnsRecords[queryName]) {
                // Write compressed name (pointer to question)
                response.writeUInt16BE(namePtr, respOffset);
                respOffset += 2;
                
                // Type A (1)
                response.writeUInt16BE(1, respOffset);
                respOffset += 2;
                
                // Class IN (1)
                response.writeUInt16BE(1, respOffset);
                respOffset += 2;
                
                // TTL (300 seconds = 5 minutes)
                response.writeUInt32BE(300, respOffset);
                respOffset += 4;
                
                // RDATA length (4 bytes for IPv4)
                response.writeUInt16BE(4, respOffset);
                respOffset += 2;
                
                // Write IP address
                const ipParts = ip.split('.').map(Number);
                for (const part of ipParts) {
                    response.writeUInt8(part, respOffset);
                    respOffset += 1;
                }
            }
        }

        // Send the response
        udpSocket.send(response.slice(0, respOffset), remoteAddr.port, remoteAddr.address);
        console.log(`Sent response for ${queryName} with ${answers} records`);

    } catch (e) {
        console.error(`Error processing DNS query: ${e}`);
    }
});

console.log("DNS server running on 127.0.0.1:2053");
