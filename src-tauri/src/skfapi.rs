//#![allow(unused)]
//use libc::*;
use libc::c_char;
use libloading::{Library, Symbol};
use std::ffi::c_void;
use std::os::raw::c_int;
use std::os::raw::c_uchar;
use std::os::raw::c_uint;
use std::ptr::null_mut;

// dll文件中的函数
// 枚举设备
// ULONG DEVAPI SKF_EnumDev(BOOL bPresent, LPSTR szNameList, ULONG *pulSize);
type SKF_EnumDev = unsafe extern "stdcall" fn(u8, *mut c_char, &c_uint) -> u32;

//连接设备
// ULONG DEVAPI SKF_ConnectDev (LPSTR szName, DEVHANDLE *phDev)
type SKF_ConnectDev = unsafe extern "stdcall" fn(*const c_char, *mut *mut c_void) -> u32;

// 断开连接
// ULONG DEVAPI SKF_DisConnectDev (DEVHANDLE hDev)
type SKF_DisConnectDev = unsafe extern "stdcall" fn(*const c_void) -> u32;

// 获取设备信息
// ULONG DEVAPI SKF_GetDevInfo (DEVHANDLE hDev, DEVINFO *pDevInfo)
type SKF_GetDevInfo = unsafe extern "stdcall" fn(*const c_void, *mut c_void) -> u32;

// 打开应用
// ULONG DEVAPI SKF_OpenApplication(DEVHANDLE hDev, LPSTR szAppName, HAPPLICATION *phApplication)
type SKF_OpenApplication =
    unsafe extern "stdcall" fn(*const c_void, *const c_char, *mut *mut c_void) -> u32;

// 关闭应用
// ULONG DEVAPI SKF_CloseApplication(HAPPLICATION hApplication)
type SKF_CloseApplication = unsafe extern "stdcall" fn(*const c_void) -> u32;

// 验证PIN码
// ULONG DEVAPI SKF_VerifyPIN (HAPPLICATION hApplication, ULONG ulPINType, LPSTR szPIN, ULONG *pulRetryCount)
type SKF_VerifyPIN = unsafe  fn(*const c_void, u32, *const c_char, *mut u32) -> u32;

// 打开容器
// ULONG DEVAPI SKF_OpenContainer(HAPPLICATION hApplication, LPSTR szContainerName, HCONTAINER *phContainer)
type SKF_OpenContainer =
    unsafe extern "stdcall" fn(*const c_void, *const c_char, *mut *mut c_void) -> u32;

// 关闭容器
// ULONG DEVAPI SKF_CloseContainer(HCONTAINER hContainer)
type SKF_CloseContainer = unsafe extern "stdcall" fn(*const c_void) -> u32;

static LIBRARB_PATH: &str = "./dll64/SKFAPI30373.dll";

// 设备句柄
static mut DEV_HANDLER: *mut c_void = null_mut();
// 应用句柄
static mut APP_HANDLER: *mut c_void = null_mut();
// 容器句柄
static mut CON_HANDLER: *mut c_void = null_mut();

pub struct SKFApi {
    pub lib: Library,
    //设备是否认证
    dev_connect_seccess: bool,
    //设备是否认证，认证成功后才可以修改设备的访问控制功能
    dev_auth_success: bool,
    //设备是否验证PIN码，验证PIN码后才能使用内部密钥的一些功能
    pin_verify_success: bool,
    //应用是否打开
    app_open_success: bool,
    //容器是否打开
    con_open_success: bool,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct VERSION {
    major: u8,
    minor: u8,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct DEVINFO {
    pub version: VERSION,
    pub  manufacturer: [u8; 64],
    pub issuer: [u8; 64],
    pub  label: [u8; 32],
    pub serial_number: [u8; 32],
    pub  hw_version: VERSION,
    pub firmware_version: VERSION,
    pub alg_sym_cap: u32,
    pub alg_asym_cap: u32,
    pub alg_hash_cap: u32,
    pub  dev_auth_alg_id: u32,
    pub total_space: u32,
    pub free_space: u32,
    pub reserved: [u8; 64],
}

impl DEVINFO {
    pub fn new() -> DEVINFO {
        DEVINFO {
            version: VERSION::default(),
            manufacturer: [0u8; 64],
            issuer: [0u8; 64],
            label: [0u8; 32],
            serial_number: [0u8; 32],
            hw_version: VERSION::default(),
            firmware_version: VERSION::default(),
            alg_sym_cap: 0,
            alg_asym_cap: 0,
            alg_hash_cap: 0,
            dev_auth_alg_id: 0,
            total_space: 0,
            free_space: 0,
            reserved: [0u8; 64],
        }
    }
}

impl SKFApi {
    pub fn new() -> SKFApi {
        let library = unsafe { Library::new(LIBRARB_PATH).unwrap() };
        SKFApi {
            lib: library,
            dev_connect_seccess: false,
            dev_auth_success: false,
            pin_verify_success: false,
            app_open_success: false,
            con_open_success: false,
        }
    }

    pub fn skf_enum_dev(&self, name_vec: &mut Vec<String>, device_num: &mut u32) -> u32 {
        let mut name_list = [0u8; 256];
        let mut len: u32 = 256;
        let mut ret: u32 = 0;
        unsafe {
            let fn_skf_enum_dev: Symbol<SKF_EnumDev> = self.lib.get(b"SKF_EnumDev").unwrap();
            ret = fn_skf_enum_dev(1, name_list.as_mut_ptr() as *mut i8, &len);
        }

        if ret != 0 {
            return ret;
        }
        if len == 0 {
            *device_num = 0;
            return 0;
        }

        let mut split_index: usize = 0;
        for (i, _) in name_list.iter().enumerate() {
            if i as u32 > len - 1 {
                break;
            }
            if name_list[i] as char == '\0' {
                let name_s = &name_list[split_index..i];
                let device_name = unsafe { String::from_utf8_unchecked(name_s.to_vec()) };
                name_vec.push(device_name);
                split_index = i + 1;
                *device_num += 1;

                if name_list[i + 1] as char == '\0' {
                    break;
                }
            }
        }
        return 0;
    }

    pub fn skf_connect_dev(&mut self, dev_name_str: &str) -> u32 {
        println!("skf_connect_dev -> ready connect device: {}", dev_name_str);

        let mut ret: u32 = 0;
        // let mut dev_handler: *mut c_void = null_mut();
        unsafe {
            let mut device_name = String::from(dev_name_str);
            //动态库必须接收\0结束的字符串
            device_name.push('\0');

            let fn_skf_connect_dev: Symbol<SKF_ConnectDev> =
                self.lib.get(b"SKF_ConnectDev").unwrap();
            ret = fn_skf_connect_dev(device_name.as_mut_ptr() as *const i8, &mut DEV_HANDLER);
        }
        if ret != 0 {
            return ret;
        }
        self.dev_connect_seccess = true;
        return 0;
    }


    pub fn skf_get_dev_info(&self, dev_info: *mut DEVINFO) -> u32 {
        let mut ret: u32 = 0;

        unsafe {
            // let mut dev_info = DEVINFO::new();
            
            let fn_skf_get_dev_info: Symbol<SKF_GetDevInfo> =
                self.lib.get(b"SKF_GetDevInfo").unwrap();
            ret = fn_skf_get_dev_info(DEV_HANDLER, dev_info as *mut c_void);
        }

        if ret != 0 {
            return ret;
        }

        return 0;
    }

    pub fn skf_disconnect_dev(&mut self) -> u32 {
        let mut ret: u32 = 0;
        unsafe {
            let fn_skf_disconnect_dev: Symbol<SKF_DisConnectDev> =
                self.lib.get(b"SKF_DisConnectDev").unwrap();
            ret = fn_skf_disconnect_dev(DEV_HANDLER);
        }
        if ret != 0 {
            return ret;
        }
        self.dev_connect_seccess = false;
        return 0;
    }

    pub fn skf_open_application(&mut self, app_name_str: &str) -> u32 {
        println!(
            "skf_open_application -> ready open application: {}",
            app_name_str
        );

        let mut ret: u32 = 0;

        unsafe {
            let mut application_name = String::from(app_name_str);
            //动态库必须接收\0结束的字符串
            application_name.push('\0');

            let fn_skf_open_application: Symbol<SKF_OpenApplication> =
                self.lib.get(b"SKF_OpenApplication").unwrap();
            ret = fn_skf_open_application(
                DEV_HANDLER,
                application_name.as_mut_ptr() as *const i8,
                &mut APP_HANDLER,
            );
        }
        if ret != 0 {
            return ret;
        }
        self.app_open_success = true;
        return 0;
    }

    pub fn skf_close_application(&mut self) -> u32 {
        let mut ret: u32 = 0;
        unsafe {
            let fn_skf_close_application: Symbol<SKF_CloseApplication> =
                self.lib.get(b"SKF_CloseApplication").unwrap();
            ret = fn_skf_close_application(APP_HANDLER);
        }
        if ret != 0 {
            return ret;
        }
        self.app_open_success = false;
        return 0;
    }

    pub fn skf_open_container(&mut self, con_name_str: &str) -> u32 {
        println!(
            "skf_open_container -> ready open container: {}",
            con_name_str
        );

        let mut ret: u32 = 0;

        unsafe {
            let mut container_name = String::from(con_name_str);
            //动态库必须接收\0结束的字符串
            container_name.push('\0');

            let fn_skf_open_container: Symbol<SKF_OpenContainer> =
                self.lib.get(b"SKF_OpenContainer").unwrap();
            ret = fn_skf_open_container(
                APP_HANDLER,
                container_name.as_mut_ptr() as *const c_char,
                &mut CON_HANDLER,
            );
        }
        if ret != 0 {
            return ret;
        }
        self.con_open_success = true;
        return 0;
    }

    pub fn skf_close_container(&mut self) -> u32 {
        let mut ret: u32 = 0;

        if !self.con_open_success {}

        unsafe {
            let fn_skf_close_container: Symbol<SKF_CloseContainer> =
                self.lib.get(b"SKF_CloseContainer").unwrap();
            ret = fn_skf_close_container(CON_HANDLER);
        }
        if ret != 0 {
            return ret;
        }
        self.con_open_success = false;
        return 0;
    }

    pub fn skf_verify_pin(&mut self, pin_str: &str, retry_count: *mut u32) -> u32 {
        println!("skf_verify_pin -> ready verify pin code: {}", pin_str);
        let mut ret: u32 = 0;

        if !self.app_open_success {}

        unsafe {
            let mut pin = String::from(pin_str);
            //动态库必须接收\0结束的字符串
            pin.push('\0');

            let fn_skf_verify_pin: Symbol<SKF_VerifyPIN> = self.lib.get(b"SKF_VerifyPIN").unwrap();
            ret = fn_skf_verify_pin(
                APP_HANDLER,
                1,//1:USER_TYPE, 0:ADMIN_TYPE
                pin.as_mut_ptr() as *const c_char,
                retry_count,
            );
        }

        if ret != 0 {
            return ret;
        }

        self.pin_verify_success = true;
        return 0;
    }
}
