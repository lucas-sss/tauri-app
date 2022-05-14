//#![allow(unused)]
use libc::c_char;
use libloading::{Library, Symbol};
use std::ffi::c_void;
use std::mem;
use std::os::raw::c_uint;
use std::ptr::null_mut;

// dll文件中的函数
// 枚举设备
// ULONG DEVAPI SKF_EnumDev(BOOL bPresent, LPSTR szNameList, ULONG *pulSize);
type SKF_EnumDev = unsafe extern "stdcall" fn(u8, *mut c_char, &c_uint) -> u32;

//连接设备
// ULONG DEVAPI SKF_ConnectDev(LPSTR szName, DEVHANDLE *phDev)
type SKF_ConnectDev = unsafe extern "stdcall" fn(*const c_char, *mut *mut c_void) -> u32;

// 断开连接
// ULONG DEVAPI SKF_DisConnectDev(DEVHANDLE hDev)
type SKF_DisConnectDev = unsafe extern "stdcall" fn(*const c_void) -> u32;

// 获取设备信息
// ULONG DEVAPI SKF_GetDevInfo(DEVHANDLE hDev, DEVINFO *pDevInfo)
// type SKF_GetDevInfo = unsafe extern "stdcall" fn(*const c_void, *mut c_void) -> u32;
type SKF_GetDevInfo = unsafe extern "stdcall" fn(*const c_void, *mut DEVINFO) -> u32;

// 生成随机数
// ULONG DEVAPI SKF_GenRandom(DEVHANDLE hDev, BYTE *pbRandom, ULONG ulRandomLen)
type SKF_GenRandom = unsafe extern "stdcall" fn(*const c_void, *mut c_void, u32) -> u32;

// 密码杂凑初始化
// ULONG DEVAPI SKF_DigestInit(DEVHANDLE hDev, ULONG ulAlgID, ECCPUBLICKEYBLOB *pPubKey, unsigned char *pucID, ULONG ulIDLen, HANDLE *phHash)
type SKF_DigestInit = unsafe extern "stdcall" fn(
    *const c_void,
    u32,
    *const ECCPUBLICKEYBLOB,
    *const c_void,
    u32,
    *mut *mut c_void,
) -> u32;

// 单组数据密码杂凑
// ULONG DEVAPI SKF_Digest(HANDLE hHash, BYTE *pbData, ULONG ulDataLen, BYTE *pbHashData, ULONG *pulHashLen)

// 多组数据密码杂凑
// ULONG DEVAPI SKF_DigestUpdate(HANDLE hHash, BYTE *pbData, ULONG ulDataLen)
type SKF_DigestUpdate = unsafe extern "stdcall" fn(*const c_void, *const c_void, u32) -> u32;

// 结束密码杂凑
// ULONG DEVAPI SKF_DigestFinal(HANDLE hHash, BYTE *pHashData, ULONG *pulHashLen)
type SKF_DigestFinal = unsafe extern "stdcall" fn(*const c_void, *const c_void, *mut u32) -> u32;

// 枚举应用

// 打开应用
// ULONG DEVAPI SKF_OpenApplication(DEVHANDLE hDev, LPSTR szAppName, HAPPLICATION *phApplication)
type SKF_OpenApplication =
    unsafe extern "stdcall" fn(*const c_void, *const c_char, *mut *mut c_void) -> u32;

// 验证PIN码
// ULONG DEVAPI SKF_VerifyPIN (HAPPLICATION hApplication, ULONG ulPINType, LPSTR szPIN, ULONG *pulRetryCount)
type SKF_VerifyPIN = unsafe fn(*const c_void, u32, *const c_char, *mut u32) -> u32;

// 修改PIN码
// ULONG DEVAPI SKF_ChangePIN (HAPPLICATION hApplication, ULONG ulPINType, LPSTR szOldPin, LPSTR szNewPin, ULONG *pulRetryCount)
type SKF_ChangePIN =
    unsafe extern "stdcall" fn(*const c_void, u32, *const c_char, *const c_char, *mut u32) -> u32;

// 关闭应用
// ULONG DEVAPI SKF_CloseApplication(HAPPLICATION hApplication)
type SKF_CloseApplication = unsafe extern "stdcall" fn(*const c_void) -> u32;

// 枚举容器
// ULONG DEVAPI SKF_EnumContainer(HAPPLICATION hApplication, LPSTR szContainerName,ULONG *pulSize)
type SKF_EnumContainer = unsafe extern "stdcall" fn(*const c_void, *mut c_char, *mut u32) -> u32;

// 打开容器
// ULONG DEVAPI SKF_OpenContainer(HAPPLICATION hApplication, LPSTR szContainerName, HCONTAINER *phContainer)
type SKF_OpenContainer =
    unsafe extern "stdcall" fn(*const c_void, *const c_char, *mut *mut c_void) -> u32;

// ECC签名
// ULONG DEVAPI SKF_ECCSignData (HCONTAINER hContainer, BYTE *pbData, ULONG ulDataLen, PECCSIGNATUREBLOB pSignature)
type SKF_ECCSignData =
    unsafe extern "stdcall" fn(*const c_void, *const c_void, u32, *mut ECCSIGNATUREBLOB) -> u32;

// 导出数字证书
// ULONG DEVAPI SKF_ExportCertificate(HCONTAINER hContainer, BOOL bSignFlag, BYTE* pbCert, ULONG *pulCertLen)
type SKF_ExportCertificate =
    unsafe extern "stdcall" fn(*const c_void, u8, *mut c_void, *mut u32) -> u32;

// 导出公钥
// ULONG DEVAPI SKF_ExportPublicKey (HCONTAINER hContainer, BOOL bSignFlag, BYTE* pbBlob, ULONG* pulBlobLen)
type SKF_ExportPublicKey =
    unsafe extern "stdcall" fn(*const c_void, u8, *mut ECCPUBLICKEYBLOB, *mut u32) -> u32;

// 关闭容器
// ULONG DEVAPI SKF_CloseContainer(HCONTAINER hContainer)
type SKF_CloseContainer = unsafe extern "stdcall" fn(*const c_void) -> u32;

#[warn(dead_code)]
pub mod skf_err_code {
    pub static SAR_OK: u32 = 0x00000000; //成功
    pub static SAR_FAIL: u32 = 0x0A000001; //失败
    pub static SAR_UNKNOWNERR: u32 = 0x0A000002; //异常错误
    pub static SAR_NOTSUPPORTYETERR: u32 = 0x0A000003; //不支持的服务
    pub static SAR_FILEERR: u32 = 0x0A000004; //文件操作错误
    pub static SAR_INVALIDHANDLEERR: u32 = 0x0A000005; //无效的句柄
    pub static SAR_INVALIDPARAMERR: u32 = 0x0A000006; //无效的参数
    pub static SAR_READFILEERR: u32 = 0x0A000007; //读文件错误
    pub static SAR_WRITEFILEERR: u32 = 0x0A000008; //写文件错误
    pub static SAR_NAMELENERR: u32 = 0x0A000009; //名称长度错误
    pub static SAR_KEYUSAGEERR: u32 = 0x0A00000A; //密钥用途错误
    pub static SAR_MODULUSLENERR: u32 = 0x0A00000B; //模的长度错误
    pub static SAR_NOTINITIALIZEERR: u32 = 0x0A00000C; //未初始化
    pub static SAR_OBJERR: u32 = 0x0A00000D; //对象错误
    pub static SAR_MEMORYERR: u32 = 0x0A00000E; //内存错误
    pub static SAR_TIMEOUTERR: u32 = 0x0A00000F; //超时
    pub static SAR_INDATALENERR: u32 = 0x0A000010; //输入数据长度错误
    pub static SAR_INDATAERR: u32 = 0x0A000011; //输入数据错误
    pub static SAR_GENRANDERR: u32 = 0x0A000012; //生成随机数错误
    pub static SAR_HASHOBJERR: u32 = 0x0A000013; //HASH 对象错
    pub static SAR_HASHERR: u32 = 0x0A000014; //HASH 运算错误
    pub static SAR_GENRSAKEYERR: u32 = 0x0A000015; //产生 RSA 密钥错
    pub static SAR_RSAMODULUSLENERR: u32 = 0x0A000016; //RSA 密钥模长错误
    pub static SAR_CSPIMPRTPUBKEYERR: u32 = 0x0A000017; //CSP 服务导入公钥错误
    pub static SAR_RSAENCERR: u32 = 0x0A000018; //RSA 加密错误
    pub static SAR_RSADECERR: u32 = 0x0A000019; //RSA 解密错误
    pub static SAR_HASHNOTEQUALERR: u32 = 0x0A00001A; //HASH 值不相等
    pub static SAR_KEYNOTFOUNTERR: u32 = 0x0A00001B; //密钥未发现
    pub static SAR_CERTNOTFOUNTERR: u32 = 0x0A00001C; //证书未发现
    pub static SAR_NOTEXPORTERR: u32 = 0x0A00001D; //对象未导出
    pub static SAR_DECRYPTPADERR: u32 = 0x0A00001E; //解密时做补丁错误
    pub static SAR_MACLENERR: u32 = 0x0A00001F; //MAC 长度错误
    pub static SAR_BUFFER_TOO_SMALL: u32 = 0x0A000020; //缓冲区不足
    pub static SAR_KEYINFOTYPEERR: u32 = 0x0A000021; //密钥类型错误
    pub static SAR_NOT_EVENTERR: u32 = 0x0A000022; //无事件错误
    pub static SAR_DEVICE_REMOVED: u32 = 0x0A000023; //设备已移除
    pub static SAR_PIN_INCORRECT: u32 = 0x0A000024; //PIN 不正确
    pub static SAR_PIN_LOCKED: u32 = 0x0A000025; //PIN 被锁死
    pub static SAR_PIN_INVALID: u32 = 0x0A000026; //PIN 无效
    pub static SAR_PIN_LEN_RANGE: u32 = 0x0A000027; //PIN 长度错误
    pub static SAR_USER_ALREADY_LOGGED_IN: u32 = 0x0A000028; //用户已经登录
    pub static SAR_USER_PIN_NOT_INITIALIZED: u32 = 0x0A000029; //没有初始化用户口令
    pub static SAR_USER_TYPE_INVALID: u32 = 0x0A00002A; //PIN 类型错误
    pub static SAR_APPLICATION_NAME_INVALID: u32 = 0x0A00002B; //应用名称无效
    pub static SAR_APPLICATION_EXISTS: u32 = 0x0A00002C; //应用已经存在
    pub static SAR_USER_NOT_LOGGED_IN: u32 = 0x0A00002D; //用户没有登录
    pub static SAR_APPLICATION_NOT_EXISTS: u32 = 0x0A00002E; //应用不存在
    pub static SAR_FILE_ALREADY_EXIST: u32 = 0x0A00002F; //文件已经存在
    pub static SAR_NO_ROOM: u32 = 0x0A000030; //空间不足
    pub static SAR_FILE_NOT_EXIST: u32 = 0x0A000031; //文件不存在
    pub static SAR_REACH_MAX_CONTAINER_COUNT: u32 = 0x0A000032; //已达到最大可管理容器数
}

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
    pub manufacturer: [u8; 64],
    pub issuer: [u8; 64],
    pub label: [u8; 32],
    pub serial_number: [u8; 32],
    pub hw_version: VERSION,
    pub firmware_version: VERSION,
    pub alg_sym_cap: u32,
    pub alg_asym_cap: u32,
    pub alg_hash_cap: u32,
    pub dev_auth_alg_id: u32,
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

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ECCPUBLICKEYBLOB {
    pub BitLen: u32,
    pub XCoordinate: [u8; 64],
    pub YCoordinate: [u8; 64],
}

impl ECCPUBLICKEYBLOB {
    pub fn new() -> ECCPUBLICKEYBLOB {
        ECCPUBLICKEYBLOB {
            BitLen: 256,
            XCoordinate: [0u8; 64],
            YCoordinate: [0u8; 64],
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ECCPRIVATEKEYBLOB {
    pub BitLen: u32,
    pub PrivateKey: [u8; 64],
}

impl ECCPRIVATEKEYBLOB {
    pub fn new() -> ECCPRIVATEKEYBLOB {
        ECCPRIVATEKEYBLOB {
            BitLen: 256,
            PrivateKey: [0u8; 64],
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ECCCIPHERBLOB {
    pub XCoordinate: [u8; 64],
    pub YCoordinate: [u8; 64],
    pub Hash: [u8; 32],
    pub CipherLen: u32,
    pub Cipher: [u8; 113],
}

impl ECCCIPHERBLOB {
    pub fn new() -> ECCCIPHERBLOB {
        ECCCIPHERBLOB {
            XCoordinate: [0u8; 64],
            YCoordinate: [0u8; 64],
            Hash: [0u8; 32],
            CipherLen: 0,
            Cipher: [0u8; 113],
        }
    }
}

pub struct ECCSIGNATUREBLOB {
    pub r: [u8; 64],
    pub s: [u8; 64],
}

impl ECCSIGNATUREBLOB {
    pub fn new() -> ECCSIGNATUREBLOB {
        ECCSIGNATUREBLOB {
            r: [0u8; 64],
            s: [0u8; 64],
        }
    }

    pub fn to_string(&self) -> String {
        let mut str = String::from("");
        let r = &self.r[32..];
        let s = &self.s[32..];
        str.push_str(&hex::encode(r).to_uppercase());
        str.push_str(&hex::encode(s).to_uppercase());
        return str;
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
            // ret = fn_skf_get_dev_info(DEV_HANDLER, dev_info as *mut c_void);
            ret = fn_skf_get_dev_info(DEV_HANDLER, dev_info);
        }

        if ret != 0 {
            return ret;
        }

        return 0;
    }

    pub fn skf_gen_random(&mut self, random: &mut [u8], len: u32) -> u32 {
        let mut ret: u32 = 0;
        unsafe {
            let fn_skf_gen_random: Symbol<SKF_GenRandom> = self.lib.get(b"SKF_GenRandom").unwrap();
            ret = fn_skf_gen_random(DEV_HANDLER, random.as_mut_ptr() as *mut c_void, len);
        }
        if ret != 0 {
            println!("skf_gen_random -> SKF_GenRandom fail, ret: {:x}", ret);
            return ret;
        }
        return 0;
    }

    pub fn skf_hash(
        &mut self,
        data: &[u8],
        data_len: u32,
        hash: &mut [u8; 32],
        pre_process: bool,
        pubkey: Option<ECCPUBLICKEYBLOB>,
    ) -> u32 {
        let mut ret: u32 = 0;
        let mut hash_len: u32 = 32;
        //密码杂凑算法标识
        let SGD_SM3: u32 = 0x00000001;
        let mut HASH_HANDLER: *mut c_void = null_mut();

        unsafe {
            let fn_skf_digest_init: Symbol<SKF_DigestInit> =
                self.lib.get(b"SKF_DigestInit").unwrap();

            match pubkey {
                Some(key) => {
                    ret = fn_skf_digest_init(
                        DEV_HANDLER,
                        SGD_SM3,
                        &key,
                        "1234567812345678".as_bytes().as_ptr() as *const c_void,
                        16,
                        &mut HASH_HANDLER,
                    );
                }
                None => {
                    ret = fn_skf_digest_init(
                        DEV_HANDLER,
                        SGD_SM3,
                        null_mut(),
                        null_mut(),
                        0,
                        &mut HASH_HANDLER,
                    );
                }
            }
        }
        if ret != 0 {
            println!("skf_hash -> SKF_DigestInit fail, ret: {:x}", ret);
            return ret;
        }
        unsafe {
            let fn_skf_digest_update: Symbol<SKF_DigestUpdate> =
                self.lib.get(b"SKF_DigestUpdate").unwrap();
            ret = fn_skf_digest_update(HASH_HANDLER, data.as_ptr() as *const c_void, data_len);
        }
        if ret != 0 {
            println!("skf_hash -> SKF_DigestUpdate fail, ret: {:x}", ret);
            return ret;
        }

        unsafe {
            let fn_skf_digest_final: Symbol<SKF_DigestFinal> =
                self.lib.get(b"SKF_DigestFinal").unwrap();
            ret = fn_skf_digest_final(
                HASH_HANDLER,
                hash.as_mut_ptr() as *const c_void,
                &mut hash_len,
            );
        }
        if ret != 0 {
            println!("skf_hash -> SKF_DigestFinal fail, ret: {:x}", ret);
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


    pub fn skf_enum_container(&self, name_vec: &mut Vec<String>, device_num: &mut u32) -> u32 {
        let mut name_list = [0u8; 256];
        let mut len: u32 = 256;
        let mut ret: u32 = 0;
        unsafe {
            let fn_skf_enum_container: Symbol<SKF_EnumContainer> = self.lib.get(b"SKF_EnumContainer").unwrap();
            ret = fn_skf_enum_container(APP_HANDLER, name_list.as_mut_ptr() as *mut i8, &mut len);
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
                1, //1:USER_TYPE, 0:ADMIN_TYPE
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

    pub fn skf_change_pin(
        &mut self,
        old_pin_str: &str,
        new_pin_str: &str,
        retry_count: &mut u32,
    ) -> u32 {
        let mut ret: u32 = 0;

        unsafe {
            let mut old_pin = String::from(old_pin_str);
            let mut new_pin = String::from(new_pin_str);
            //动态库必须接收\0结束的字符串
            old_pin.push('\0');
            new_pin.push('\0');

            let fn_skf_change_pin: Symbol<SKF_ChangePIN> = self.lib.get(b"SKF_ChangePIN").unwrap();
            ret = fn_skf_change_pin(
                APP_HANDLER,
                1, //1:USER_TYPE, 0:ADMIN_TYPE
                old_pin.as_mut_ptr() as *const c_char,
                new_pin.as_mut_ptr() as *const c_char,
                retry_count,
            );
        }

        if ret != 0 {
            return ret;
        }
        return 0;
    }

    pub fn skf_sign(
        &mut self,
        data: &[u8],
        data_len: u32,
        signature: &mut ECCSIGNATUREBLOB,
    ) -> u32 {
        let mut ret: u32 = 0;

        unsafe {
            let fn_skf_ecc_sign_data: Symbol<SKF_ECCSignData> =
                self.lib.get(b"SKF_ECCSignData").unwrap();
            ret = fn_skf_ecc_sign_data(
                CON_HANDLER,
                data.as_ptr() as *const c_void,
                data_len,
                signature,
            );
        }
        if ret != 0 {
            return ret;
        }

        return 0;
    }

    pub fn skf_export_cert(&mut self, sign: bool, data: &mut [u8], data_len: *mut u32) -> u32 {
        let mut ret: u32 = 0;
        unsafe {
            let fn_skf_export_certificate: Symbol<SKF_ExportCertificate> =
                self.lib.get(b"SKF_ExportCertificate").unwrap();
            if sign {
                ret = fn_skf_export_certificate(
                    CON_HANDLER,
                    1,
                    data.as_mut_ptr() as *mut c_void,
                    data_len,
                );
            } else {
                ret = fn_skf_export_certificate(
                    CON_HANDLER,
                    0,
                    data.as_mut_ptr() as *mut c_void,
                    data_len,
                );
            }
        }
        if ret != 0 {
            return ret;
        }
        return 0;
    }

    pub fn skf_export_public_key(&mut self, sign: bool, pubkey: &mut ECCPUBLICKEYBLOB) -> u32 {
        let mut ret: u32 = 0;

        let mut len = mem::size_of::<ECCPUBLICKEYBLOB>() as u32;
        unsafe {
            let fn_skf_export_public_key: Symbol<SKF_ExportPublicKey> =
                self.lib.get(b"SKF_ExportPublicKey").unwrap();
            if sign {
                ret = fn_skf_export_public_key(CON_HANDLER, 1, pubkey, &mut len);
            } else {
                ret = fn_skf_export_public_key(CON_HANDLER, 0, pubkey, &mut len);
            }
        }
        if ret != 0 {
            return ret;
        }
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
}
