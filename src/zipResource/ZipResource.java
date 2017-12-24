package zipResource;

import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLConnection;

import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import javax.imageio.ImageIO;
import javax.swing.ImageIcon;

/**
 *
 * @author bmadov 7-zip with password /store /zipcrypto
 */
public class ZipResource extends InputStream {

    private static final int[] CRC_TABLE = new int[256];

    // compute the table
    // (could also have it pre-computed - see http://snippets.dzone.com/tag/crc32)
    static {
        for (int i = 0; i < 256; i++) {
            int r = i;
            for (int j = 0; j < 8; j++) {
                if ((r & 1) == 1) {
                    r = (r >>> 1) ^ 0xedb88320;
                } else {
                    r >>>= 1;
                }
            }
            CRC_TABLE[i] = r;
        }
    }

    private static final int DECRYPT_HEADER_SIZE = 12;
    private static final int[] LFH_SIGNATURE = {0x50, 0x4b, 0x03, 0x04};

    private final InputStream delegate;
    private final String password;
    private final int keys[] = new int[3];

    private State state = State.SIGNATURE;
    private int skipBytes;
    private int compressedSize;
    private int value;
    private int valuePos;
    private int valueInc;

    public ZipResource(InputStream stream, String password) {
        this.delegate = stream;
        this.password = password;
    }

    @Override
    public int read() throws IOException {
        int result = delegate.read();
        if (skipBytes == 0) {
            switch (state) {
                case SIGNATURE:
                    if (result != LFH_SIGNATURE[valuePos]) {
                        state = State.TAIL;
                    } else {
                        valuePos++;
                        if (valuePos >= LFH_SIGNATURE.length) {
                            skipBytes = 2;
                            state = State.FLAGS;
                        }
                    }
                    break;
                case FLAGS:
                    if ((result & 1) == 0) {
                        throw new IllegalStateException("ZIP not password protected.");
                    }
                    if ((result & 64) == 64) {
                        throw new IllegalStateException("Strong encryption used.");
                    }
                    if ((result & 8) == 8) {
                        throw new IllegalStateException("Unsupported ZIP format.");
                    }
                    result -= 1;
                    compressedSize = 0;
                    valuePos = 0;
                    valueInc = DECRYPT_HEADER_SIZE;
                    state = State.COMPRESSED_SIZE;
                    skipBytes = 11;
                    break;
                case COMPRESSED_SIZE:
                    compressedSize += result << (8 * valuePos);
                    result -= valueInc;
                    if (result < 0) {
                        valueInc = 1;
                        result += 256;
                    } else {
                        valueInc = 0;
                    }
                    valuePos++;
                    if (valuePos > 3) {
                        valuePos = 0;
                        value = 0;
                        state = State.FN_LENGTH;
                        skipBytes = 4;
                    }
                    break;
                case FN_LENGTH:
                case EF_LENGTH:
                    value += result << 8 * valuePos;
                    if (valuePos == 1) {
                        valuePos = 0;
                        if (state == State.FN_LENGTH) {
                            state = State.EF_LENGTH;
                        } else {
                            state = State.HEADER;
                            skipBytes = value;
                        }
                    } else {
                        valuePos = 1;
                    }
                    break;
                case HEADER:
                    initKeys(password);
                    for (int i = 0; i < DECRYPT_HEADER_SIZE; i++) {
                        updateKeys((byte) (result ^ decryptByte()));
                        result = delegate.read();
                    }
                    compressedSize -= DECRYPT_HEADER_SIZE;
                    state = State.DATA;
                // intentionally no break
                case DATA:
                    result = (result ^ decryptByte()) & 0xff;
                    updateKeys((byte) result);
                    compressedSize--;
                    if (compressedSize == 0) {
                        valuePos = 0;
                        state = State.SIGNATURE;
                    }
                    break;
                case TAIL:
                // do nothing
            }
        } else {
            skipBytes--;
        }
        return result;
    }

    @Override
    public void close() throws IOException {
        delegate.close();
        super.close();
    }

    private void initKeys(String password) {
        keys[0] = 305419896;
        keys[1] = 591751049;
        keys[2] = 878082192;
        for (int i = 0; i < password.length(); i++) {
            updateKeys((byte) (password.charAt(i) & 0xff));
        }
    }

    private void updateKeys(byte charAt) {
        keys[0] = crc32(keys[0], charAt);
        keys[1] += keys[0] & 0xff;
        keys[1] = keys[1] * 134775813 + 1;
        keys[2] = crc32(keys[2], (byte) (keys[1] >> 24));
    }

    private byte decryptByte() {
        int temp = keys[2] | 2;
        return (byte) ((temp * (temp ^ 1)) >>> 8);
    }

    private int crc32(int oldCrc, byte charAt) {
        return ((oldCrc >>> 8) ^ CRC_TABLE[(oldCrc ^ charAt) & 0xff]);
    }

    private static enum State {
        SIGNATURE, FLAGS, COMPRESSED_SIZE, FN_LENGTH, EF_LENGTH, HEADER, DATA, TAIL
    }

    private static InputStream readZipSifra(URL zipname, String password, String filename) throws IOException, URISyntaxException {

        URLConnection connection = zipname.openConnection();

        try (
            // password-protected zip file I need to read
            InputStream in = connection.getInputStream();
            // wrap it in the decrypt stream
            ZipResource zdis = new ZipResource(in, password);            
            // wrap the decrypt stream by the ZIP input stream
            ZipInputStream zis = new ZipInputStream(zdis)) {
            // read all the zip entries and save them as files
            ZipEntry ze;

            while ((ze = zis.getNextEntry()) != null) {
                if (ze.getName().equals(filename)) {
                    InputStream is = convertZipInputStreamToInputStream(zis, ze);
                    zis.closeEntry();
                    return is;
                }
            }
        }
        return null;
    }

    private static InputStream convertZipInputStreamToInputStream(ZipInputStream in, ZipEntry entry) throws IOException {
        final int BUFFER = 2048;
        int count = 0;
        byte data[] = new byte[BUFFER];
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        while ((count = in.read(data, 0, BUFFER)) != -1) {
            out.write(data);
        }
        InputStream is = new ByteArrayInputStream(out.toByteArray());
        return is;
    }    

    private static byte[] getImage(InputStream in) {
        try {
            BufferedImage image = ImageIO.read(in); //just checking if the InputStream belongs in fact to an image
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            ImageIO.write(image, "png", baos);
            return baos.toByteArray();
        } catch (IOException e) {
            // do something, it is not a image
            e.printStackTrace();
        }
        return null;
    }

    public static ImageIcon loadImageFromZip(URL zipfile, String password, String fileName) throws IOException, URISyntaxException {
        try {
            byte[] bytes = getImage(readZipSifra(zipfile, password, fileName));
            BufferedImage img = ImageIO.read(new ByteArrayInputStream(bytes));
            System.out.println("img created");
            ImageIcon icon = new ImageIcon(img);
            return icon;
        } catch (IOException e) {
            // do something, it is not a image
            e.printStackTrace();
        }
        return null;

    }

}
