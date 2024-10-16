// Based on a StackOverflow answer: https://stackoverflow.com/a/12486703/85032
// Author: @rodrigo
// License: Creative Commons Attribution-ShareAlike 4.0 (https://creativecommons.org/licenses/by-sa/4.0/)

package es.goitia.pe;

import lombok.Builder;
import lombok.Data;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 * Represents version information extracted from an executable file.
 */
@Data
@Builder(builderClassName = "Builder")
public class PEInfo {
    /**
     * Other values
     */
    private Map<String, String> values;
    private String fileDescription;
    /**
     * Version of the file. This is the primary version to read
     */
    private String fileVersion;
    private String productVersion;
    private String productName;
    private String internalName;
    private String legalCopyright;
    private String originalFilename;
    private String comments;

    /**
     * Reads a single byte from the buffer and returns it as an integer.
     *
     * @param p      the byte buffer
     * @param offset the offset to read from
     * @return the byte value as an integer
     */
    private static int READ_BYTE(byte[] p, int offset) {
        return p[offset] & 0xFF;
    }

    /**
     * Reads two bytes from the buffer and combines them into a word (16-bit value).
     *
     * @param p      the byte buffer
     * @param offset the offset to read from
     * @return the word value
     */
    private static int READ_WORD(byte[] p, int offset) {
        return READ_BYTE(p, offset) | (READ_BYTE(p, offset + 1) << 8);
    }

    /**
     * Reads four bytes from the buffer and combines them into a double word (32-bit value).
     *
     * @param p      the byte buffer
     * @param offset the offset to read from
     * @return the double word value
     */
    private static int READ_DWORD(byte[] p, int offset) {
        return READ_WORD(p, offset) | (READ_WORD(p, offset + 2) << 16);
    }

    /**
     * Pads the given value to align it to the next multiple of 4.
     *
     * @param x the value to pad
     * @return the padded value
     */
    private static int PAD(int x) {
        return (x + 3) & 0xFFFFFFFC;
    }

    /**
     * Processes the given buffer to extract version information.
     *
     * @param buf the buffer containing the executable data
     * @return the extracted version information
     */
    public static PEInfo process(byte[] buf) {
        Builder builder = PEInfo.builder().values(new HashMap<>());
        byte[] version = findVersion(buf);
        if (version != null) {
            parseVersion(version, 0, builder);
        }
        return builder.build();
    }

    /**
     * Reads the file from the given path and processes it to extract version information.
     *
     * @param path the path to the executable file
     * @return the extracted version information
     * @throws IOException if an I/O error occurs
     */
    public static PEInfo process(Path path) throws IOException {
        byte[] buf = Files.readAllBytes(path);
        return process(buf);
    }

    /**
     * Finds the version resource in the given buffer.
     *
     * @param buf the buffer containing the executable data
     * @return the version resource data, or null if not found
     */
    private static byte[] findVersion(byte[] buf) {
        if (READ_WORD(buf, 0) != 0x5A4D) // Checks for MZ signature, indicating a valid executable
            return null;
        int peOffset = READ_DWORD(buf, 0x3C); // Offset to the PE header
        if (READ_WORD(buf, peOffset) != 0x4550) // Checks for PE signature
            return null;
        int coffOffset = peOffset + 4;

        int numSections = READ_WORD(buf, coffOffset + 2); // Number of sections
        int optHeaderSize = READ_WORD(buf, coffOffset + 16); // Size of the optional header
        if (numSections == 0 || optHeaderSize == 0)
            return null;
        int optHeaderOffset = coffOffset + 20;
        if (READ_WORD(buf, optHeaderOffset) != 0x10B) // Checks for 32-bit optional header magic
            return null;
        int dataDirOffset = optHeaderOffset + 96; // Offset to the data directories
        int vaRes = READ_DWORD(buf, dataDirOffset + 8 * 2); // Virtual address of the resource directory

        int secTableOffset = optHeaderOffset + optHeaderSize;
        for (int i = 0; i < numSections; i++) {
            int secOffset = secTableOffset + 40 * i;
            String secName = new String(Arrays.copyOfRange(buf, secOffset, secOffset + 8)).trim();

            if (!".rsrc".equals(secName)) // Look for the resource section
                continue;
            int vaSec = READ_DWORD(buf, secOffset + 12); // Virtual address of the section
            int rawDataOffset = READ_DWORD(buf, secOffset + 20); // Raw data offset of the section
            int resSecOffset = rawDataOffset + (vaRes - vaSec);

            int numNamed = READ_WORD(buf, resSecOffset + 12); // Number of named entries
            int numId = READ_WORD(buf, resSecOffset + 14); // Number of ID entries

            for (int j = 0; j < numNamed + numId; j++) {
                int resOffset = resSecOffset + 16 + 8 * j;
                int name = READ_DWORD(buf, resOffset);
                if (name != 16) // Check for version resource (RT_VERSION)
                    continue;
                int offs = READ_DWORD(buf, resOffset + 4);
                if ((offs & 0x80000000) == 0) // Check if it's a directory resource
                    return null;
                int verDirOffset = resSecOffset + (offs & 0x7FFFFFFF);
                numNamed = READ_WORD(buf, verDirOffset + 12);
                numId = READ_WORD(buf, verDirOffset + 14);
                if (numNamed == 0 && numId == 0)
                    return null;
                resOffset = verDirOffset + 16;
                offs = READ_DWORD(buf, resOffset + 4);
                if ((offs & 0x80000000) == 0) // Check if it's a directory resource
                    return null;
                verDirOffset = resSecOffset + (offs & 0x7FFFFFFF);
                numNamed = READ_WORD(buf, verDirOffset + 12);
                numId = READ_WORD(buf, verDirOffset + 14);
                if (numNamed == 0 && numId == 0)
                    return null;
                resOffset = verDirOffset + 16;
                offs = READ_DWORD(buf, resOffset + 4);
                if ((offs & 0x80000000) != 0) // Check if it's a directory resource
                    return null;
                verDirOffset = resSecOffset + offs;

                int verVa = READ_DWORD(buf, verDirOffset); // Virtual address of the version resource
                int verPtrOffset = rawDataOffset + (verVa - vaSec);
                return Arrays.copyOfRange(buf, verPtrOffset, buf.length); // Extract the version resource data
            }
        }
        return null;
    }

    /**
     * Parses the version resource data and populates the builder with the extracted information.
     *
     * @param version the version resource data
     * @param offs    the offset to start parsing from
     * @param builder the builder to populate with the extracted information
     * @return the next offset to parse from, padded to maintain alignment
     */
    private static int parseVersion(byte[] version, int offs, Builder builder) {
        offs = PAD(offs); // Align offset to the next multiple of 4
        int len = READ_WORD(version, offs); // Length of the version block
        offs += 2;
        int valLen = READ_WORD(version, offs); // Length of the value field
        offs += 2;
        int type = READ_WORD(version, offs); // Type of data (text or binary)
        offs += 2;
        StringBuilder info = new StringBuilder();
        for (int i = 0; i < 200; i++) { // Extract the key name (e.g., "FileDescription")
            int c = READ_WORD(version, offs);
            offs += 2;
            if (c == 0) break;
            info.append((char) c);
        }
        offs = PAD(offs); // Align offset
        if (type != 0) { // If it's a text field
            StringBuilder value = new StringBuilder();
            for (int i = 0; i < valLen; i++) { // Extract the value associated with the key
                int c = READ_WORD(version, offs);
                offs += 2;
                if (c == 0) break;
                value.append((char) c);
            }
            switch (info.toString()) { // Store the value in the appropriate field of the builder
                case "FileDescription":
                    builder.fileDescription(value.toString());
                    break;
                case "FileVersion":
                    builder.fileVersion(value.toString());
                    break;
                case "InternalName":
                    builder.internalName(value.toString());
                    break;
                case "LegalCopyright":
                    builder.legalCopyright(value.toString());
                    break;
                case "OriginalFilename":
                    builder.originalFilename(value.toString());
                    break;
                case "ProductName":
                    builder.productName(value.toString());
                    break;
                case "ProductVersion":
                    builder.productVersion(value.toString());
                    break;
                case "Comments":
                    builder.comments(value.toString());
                    break;
                default:
                    builder.values.put(info.toString(), value.toString()); // Store any other information in the map
                    break;
            }
        } else { // If it's a binary field
            if ("VS_VERSION_INFO".contentEquals(info)) { // Extract version numbers from fixed info
                builder.fileVersion(String.format("%d.%d.%d.%d",
                        READ_WORD(version, offs + 10),
                        READ_WORD(version, offs + 8),
                        READ_WORD(version, offs + 14),
                        READ_WORD(version, offs + 12)
                ));
                builder.productVersion(String.format("%d.%d.%d.%d",
                        READ_WORD(version, offs + 18),
                        READ_WORD(version, offs + 16),
                        READ_WORD(version, offs + 22),
                        READ_WORD(version, offs + 20)
                ));
            }
            offs += valLen;
        }
        while (offs < len) // Recursively parse any additional blocks
            offs = parseVersion(version, offs, builder);
        return PAD(offs); // Return the padded offset to maintain alignment
    }

    public static void main(String[] args) {
        if (args.length < 1) {
            System.out.println("Usage: java PeInfo <file path>");
            System.exit(1);
        }

        String filePath = args[0];
        try {
            PEInfo versionInfo = process(Paths.get(filePath));
            if (versionInfo != null) {
                System.out.println(versionInfo); // Print version information using Lombok's generated toString method
            } else {
                System.err.println("No version");
                System.exit(2);
            }
        } catch (IOException e) {
            e.printStackTrace(System.err);
            System.exit(3);
        }
    }
}
