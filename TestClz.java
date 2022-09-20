public final class TestClz {
    public static void main (String[] args) {
        for (final String arg : args) {
            if (arg.charAt(0) != 'a')
                System.out.println(arg);
        }
    }
}