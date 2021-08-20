package name.neuhalfen.cmswithbc;

/**
 * Absurdly minimalistic: Split a string by the last "|", drop this separator.
 */
public class QRCodeParser {
    public static final class QRCode{
     final String data;
     final String signature;

        public QRCode(String data, String signature) {
            this.data = data;
            this.signature = signature;
        }
    }

    public static QRCode parse(String qrcode){
        int i = qrcode.lastIndexOf("|");
        return new QRCode(qrcode.substring(0,i), qrcode.substring(i+1));
    }
}
