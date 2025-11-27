public class Chall {
   public static native void runCoffeeMachine();

   public static void main(String[] var0) {
      runCoffeeMachine();
   }

   static {
      System.loadLibrary("coffeemachine");
   }
}
