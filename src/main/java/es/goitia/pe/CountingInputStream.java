package es.goitia.pe;

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * InputStream with offset counter
 * Without custom support for {@link InputStream#mark(int)}
 */
public class CountingInputStream extends FilterInputStream {
    long offset;

    /**
     * Wraps other inputStream for counting bytes read/skipped
     *
     * @param in the underlying input stream, or <code>null</code> if
     *           this instance is to be created without an underlying stream.
     */
    protected CountingInputStream(InputStream in) {
        super(in);
    }

    public long getOffset() {
        return offset;
    }

    public void setOffset(long offset) {
        this.offset = offset;
    }

    public void resetOffset() {
        setOffset(0);
    }

    @Override
    public int read() throws IOException {
        int read = in.read();
        if (read != -1) {
            offset++;
        }
        return read;
    }

    @Override
    public int read(byte[] b, int off, int len) throws IOException {
        int read = in.read(b, off, len);
        if (read != -1) {
            offset += read;
        }
        return read;
    }

    @Override
    public long skip(long n) throws IOException {
        long skipped = in.skip(n);
        offset += skipped;
        return skipped;
    }

    public boolean skipAll(long n) throws IOException {
        long total = 0;
        while (total < n) {
            long s = skip(n - total);
            if (s == 0) {
                return false;
            }
            total += s;
        }
        return true;
    }
}
