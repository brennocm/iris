# The JNI symbols in libiris.so are bound by class and method name.
-keep class io.github.brennocm.iris.NativeProbes { native <methods>; }
