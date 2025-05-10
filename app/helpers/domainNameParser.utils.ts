export function domainNameParser(buffer: Buffer, offset: number): { name: string; newOffset: number } {
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
