// Based on a StackOverflow answer: https://stackoverflow.com/a/12486703/85032
// Author: @rodrigo
// License: Creative Commons Attribution-ShareAlike 4.0 (https://creativecommons.org/licenses/by-sa/4.0/)

package es.goitia.pe;

import lombok.Builder;
import lombok.Data;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
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
     * Reads a single byte from the input stream and returns it as an integer.
     *
     * @param is the input stream to read from
     * @return the byte value as an integer
     * @throws IOException if an I/O error occurs
     */
    private static String READ_STRING(InputStream is, int length) throws IOException {
        byte[] data = READ_BYTES(is, length);
        return data == null ? null : new String(data).trim();
    }

    /**
     * Reads a single byte from the input stream and returns it as an integer.
     *
     * @param is the input stream to read from
     * @return the byte value as an integer
     * @throws IOException if an I/O error occurs
     */
    private static byte[] READ_BYTES(InputStream is, int length) throws IOException {
        byte[] bytes = new byte[length];
        int total = 0;
        int read;
        while (total < length && (read = is.read(bytes, total, length - total)) != -1) {
            total += read;
        }
        return total < length ? null : bytes;
    }

    /**
     * Reads a single byte from the input stream and returns it as an integer.
     *
     * @param is the input stream to read from
     * @return the byte value as an integer
     * @throws IOException if an I/O error occurs
     */
    private static int READ_BYTE(InputStream is) throws IOException {
        int data = is.read() & 0xFF;
        return data;
    }

    /**
     * Reads two bytes from the input stream and combines them into a word (16-bit value).
     *
     * @param is the input stream to read from
     * @return the word value
     * @throws IOException if an I/O error occurs
     */
    private static int READ_WORD(InputStream is) throws IOException {
        int data = READ_BYTE(is) | (READ_BYTE(is) << 8);
        return data;
    }

    /**
     * Reads four bytes from the input stream and combines them into a double word (32-bit value).
     *
     * @param is the input stream to read from
     * @return the double word value
     * @throws IOException if an I/O error occurs
     */
    private static int READ_DWORD(InputStream is) throws IOException {
        int data = READ_WORD(is) | (READ_WORD(is) << 16);
        return data;
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
     * Pads the given value to align it to the next multiple of 4.
     *
     * @param x the value to pad
     * @return the padded value
     */
    private static int PAD(long x) {
        return PAD((int) x);
    }

    /**
     * Pads the given value to align it to the next multiple of 4.
     *
     * @param is the stream with offset want to pad
     * @return the padded value
     */
    private static boolean PAD(CountingInputStream is) throws IOException {
        return is.skipAll(PAD(is.getOffset()) - is.getOffset());
    }

    /**
     * Processes the given input stream to extract version information.
     *
     * @param is the input stream containing the executable data
     * @return the extracted version information
     * @throws IOException if an I/O error occurs
     */
    public static PEInfo process(InputStream is) throws IOException {
        Builder builder = PEInfo.builder().values(new HashMap<>());
        if (findVersion(new CountingInputStream(is), builder)) {
            return builder.build();
        }
        return null;
    }

    /**
     * Reads the file from the given path and processes it to extract version information.
     *
     * @param path the path to the executable file
     * @return the extracted version information
     * @throws IOException if an I/O error occurs
     */
    public static PEInfo process(Path path) throws IOException {
        try (InputStream is = Files.newInputStream(path)) {
            return process(is);
        }
    }

    /**
     * Finds the version resource in the given input stream.
     *
     * @param is      the input stream containing the executable data
     * @param builder the builder to populate with the extracted information
     * @return true if version information is found, false otherwise
     * @throws IOException if an I/O error occurs
     */
    private static boolean findVersion(CountingInputStream is, Builder builder) throws IOException {
        if (READ_WORD(is) != 0x5A4D) { // Checks for MZ signature, indicating a valid executable
            return false;
        }
        if (!is.skipAll(0x3A)) { // Skip to the PE header offset
            return false;
        }
        int peOffset = READ_DWORD(is); // Offset to the PE header
        if (!is.skipAll(peOffset - is.getOffset())) { // Skip to the PE header
            return false;
        }

        if (READ_WORD(is) != 0x4550) { // Checks for PE signature
            return false;
        }
//        is.skip(2); // Skip to COFF header
        if (!is.skipAll(2 + 2)) { // Skip to Num sections
            return false;
        }

        int numSections = READ_WORD(is); // Number of sections
        if (!is.skipAll(12)) { // Skip to the optional header size
            return false;
        }
        int optHeaderSize = READ_WORD(is); // Size of the optional header
        if (numSections == 0 || optHeaderSize == 0) {
            return false;
        }
        if (!is.skipAll(2)) { // Skip to the optional header
            return false;
        }
        long optHeaderOffset = is.getOffset();

        int magic = READ_WORD(is); // Optional header magic
        if (magic != 0x10B) { // Checks for 32-bit optional header magic
            return false;
        }
        if (!is.skipAll(94 + 8 * 2)) { // Skip to the data directories
            return false;
        }
        int vaRes = READ_DWORD(is); // Virtual address of the resource directory

        if (!is.skipAll(optHeaderSize - (is.getOffset() - optHeaderOffset))) { // Skip to the section table
            return false;
        }

        for (int i = 0; i < numSections; i++) {
            String secName = READ_STRING(is, 8); // Read section name

            if (secName == null) {
                return false;
            } else if (!".rsrc".equals(secName)) {
                if (!is.skipAll(32)) {
                    return false;
                }
                continue;
            }
            if (!is.skipAll(4)) {
                return false;
            }
            int vaSec = READ_DWORD(is); // Virtual address of the section
            if (!is.skipAll(4)) {
                return false;
            }
            int rawDataOffset = READ_DWORD(is); // Raw data offset of the section
            int resSecOffset = rawDataOffset + (vaRes - vaSec);

            if (!is.skipAll(resSecOffset - is.getOffset() + 12)) {
                return false;
            }
            int numNamed = READ_WORD(is); // Number of named entries
            int numId = READ_WORD(is); // Number of ID entries

            for (int j = 0; j < numNamed + numId; j++) {
                int resOffset = resSecOffset + 16 + 8 * j;
                if (!is.skipAll(resOffset - is.getOffset())) {
                    return false;
                }
                int name = READ_DWORD(is); // Resource name
                if (name != 16) { // Check for version resource (RT_VERSION)
                    if (!is.skipAll(4)) {
                        return false;
                    }
                    continue;
                }
                int offs = READ_DWORD(is); // Offset to the resource data
                if ((offs & 0x80000000) == 0) { // Check if it's a directory resource
                    return false;
                }

                // Process version dir
                int verDirOffset = resSecOffset + (offs & 0x7FFFFFFF);
                if (!is.skipAll(verDirOffset - is.getOffset() + 12)) {
                    return false;
                }
                numNamed = READ_WORD(is); // Number of named entries
                numId = READ_WORD(is); // Number of ID entries
                if (numNamed == 0 && numId == 0) {
                    return false;
                }
                resOffset = verDirOffset + 16;
                if (!is.skipAll(resOffset - is.getOffset() + 4)) {
                    return false;
                }
                offs = READ_DWORD(is); // Offset to the data
                if ((offs & 0x80000000) == 0) { // Check if it's a directory resource
                    return false;
                }
                verDirOffset = resSecOffset + (offs & 0x7FFFFFFF);
                if (!is.skipAll(verDirOffset - is.getOffset() + 12)) {
                    return false;
                }
                numNamed = READ_WORD(is); // Number of named entries
                numId = READ_WORD(is); // Number of ID entries
                if (numNamed == 0 && numId == 0) {
                    return false;
                }
                resOffset = verDirOffset + 16;
                if (!is.skipAll(resOffset - is.getOffset() + 4)) {
                    return false;
                }
                offs = READ_DWORD(is);
                if ((offs & 0x80000000) != 0) // Check if it's a directory resource
                    return false;
                verDirOffset = resSecOffset + offs;

                if (!is.skipAll(verDirOffset - is.getOffset())) {
                    return false;
                }
                int verVa = READ_DWORD(is); // Virtual address of the version resource
                int verPtrOffset = rawDataOffset + (verVa - vaSec);
                if (!is.skipAll(verPtrOffset - is.getOffset())) {
                    return false;
                }
                is.resetOffset();
                parseVersion(is, builder);
                return true;
            }
        }
        return false;
    }

    /**
     * Parses the version resource data and populates the builder with the extracted information.
     *
     * @param is      the input stream containing the version resource data
     * @param builder the builder to populate with the extracted information
     * @throws IOException if an I/O error occurs
     */
    private static void parseVersion(CountingInputStream is, Builder builder) throws IOException {
        if (!PAD(is)) { // Align offset to the next multiple of 4
            return;
        }
        int len = READ_WORD(is); // Length of the version block
        int valLen = READ_WORD(is); // Length of the value field
        int type = READ_WORD(is); // Type of data (text or binary)
        StringBuilder info = new StringBuilder();
        for (int i = 0; i < 200; i++) { // Extract the key name (e.g., "FileDescription")
            int c = READ_WORD(is);
            if (c == 0) break;
            info.append((char) c);
        }
        if (!PAD(is)) {
            return;
        }
        if (type != 0) { // If it's a text field
            StringBuilder value = new StringBuilder();
            for (int i = 0; i < valLen; i++) { // Extract the value associated with the key
                int c = READ_WORD(is);
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
            if (!is.skipAll(8)) {
                return;
            }
            if ("VS_VERSION_INFO".contentEquals(info)) { // Extract version numbers from fixed info
                builder.fileVersion(String.format("%2$d.%1$d.%4$d.%3$d",
                        READ_WORD(is), // Minor version
                        READ_WORD(is), // Major version
                        READ_WORD(is), // Revision number
                        READ_WORD(is)  // Build number
                ));
                builder.productVersion(String.format("%2$d.%1$d.%4$d.%3$d",
                        READ_WORD(is), // Minor version
                        READ_WORD(is), // Major version
                        READ_WORD(is), // Revision number
                        READ_WORD(is)  // Build number
                ));
            }
            if (!is.skipAll(valLen - 24)) {
                return;
            }
        }

        while (is.getOffset() < len) // Recursively parse any additional blocks
            parseVersion(is, builder);
        PAD(is); // Return the padded offset to maintain alignment
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
