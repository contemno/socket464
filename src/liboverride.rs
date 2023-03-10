#[macro_export]
macro_rules! libc_override {
    (fn $realname:ident($($paramname:ident : $paramtype:ty),*) -> $ret:ty) => {
        fn $realname($($paramname: $paramtype),*) -> $ret {
            let name = CString::new(stringify!($realname)).unwrap().into_raw();
            let ptr = unsafe {dlsym(RTLD_NEXT, name)};
            (unsafe {std::mem::transmute::<*const c_void, fn($($paramname: $paramtype),*) -> $ret>(ptr)})($($paramname),*)
        }
    }
}