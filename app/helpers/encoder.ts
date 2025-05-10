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
