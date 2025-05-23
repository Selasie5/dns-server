import * as dgram from "dgram";
import { domainNameParser } from "./helpers/domainNameParser.utils";

const udpSocket = dgram.createSocket("udp4");
udpSocket.bind(2053, "127.0.0.1");

// Domain to IP mapping (simple in-memory storage)
const dnsRecords: Record<string, string[]> = {
    'google.com.': ['142.250.190.78', '142.250.190.110'],
    'www.google.com.': ['142.250.190.100'] 
};







udpSocket.on("message", (data: Buffer, remoteAddr: dgram.RemoteInfo) => {
    try {
       
        const transactionId = data.readUInt16BE(0);
        const flags = data.readUInt16BE(2);
        const questions = data.readUInt16BE(4);
        
   
        let offset = 12;
        const { name: queryName, newOffset } = domainNameParser(data, offset);
        offset = newOffset;
        const qtype = data.readUInt16BE(offset);
        offset += 2;
        const qclass = data.readUInt16BE(offset);
        offset += 2;

        console.log(`Query for: ${queryName}, type: ${qtype}, class: ${qclass}`);

       
        const response = Buffer.alloc(512);
        let respOffset = 0;

     
        response.writeUInt16BE(transactionId, respOffset); // Transaction ID
        respOffset += 2;
        
        // Flags: QR=1, Opcode=0, AA=0, TC=0, RD=0, RA=0, Z=0, RCODE=0
        response.writeUInt16BE(0x8180, respOffset); 
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

       
        data.copy(response, respOffset, 12, offset);
        respOffset += (offset - 12);

        // Write answer section if we have records
        if (answers > 0 && qtype === 1) { 
            const namePtr = 0xc00c; 
            
            for (const ip of dnsRecords[queryName]) {
               
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
                
              
                const ipParts = ip.split('.').map(Number);
                for (const part of ipParts) {
                    response.writeUInt8(part, respOffset);
                    respOffset += 1;
                }
            }
        }

       
        udpSocket.send(response.slice(0, respOffset), remoteAddr.port, remoteAddr.address);
        console.log(`Sent response for ${queryName} with ${answers} records`);

    } catch (e) {
        console.error(`Error processing DNS query: ${e}`);
    }
});

console.log("DNS server running on 127.0.0.1:2053");
