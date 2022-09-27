public final class TestClz {
    public static final byte A = 0x00;

    private volatile int B;

    private transient TestClz next;

    public int v;

    int n;

    public static void main (String[] args) {
        for (final String arg : args) {
            if (arg.charAt(0) != 'a')
                System.out.println(arg);
        }
    }

    private void p() {
    }

    synchronized native void f();
}