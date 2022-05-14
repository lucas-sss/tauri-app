#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
    windows_subsystem = "windows"
)]

mod char_utils;
mod skfapi;

use crate::char_utils::*;
use crate::skfapi::{SKFApi, DEVINFO, ECCPUBLICKEYBLOB, ECCSIGNATUREBLOB};
use skfapi::skf_err_code;

use mac_address;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};
use tauri::{State, Window};

static RET_UKEY_NOT_INIT_ERROR: u32 = 221;
static RET_UKEY_ILLEGAL_ERROR: u32 = 222; //非法ukey

static RET_NOT_LOGIN_ERROR: u32 = 301;
static RET_CIPHER_LENGTH_ERROR: u32 = 301;
static RET_GET_UKEY_INFO_FAIL: u32 = 302;
static RET_NOT_EXIST_ROLE: u32 = 303;
static RET_UKEY_NOT_MATCH_ROLE: u32 = 304;
static RET_GET_IDENTITY_FAIL: u32 = 305;
static RET_GENERATE_RANDOM_FAIL: u32 = 306;
static RET_ENCRYPT_CIPHER_FAIL: u32 = 307;
static RET_EXPORT_SIGN_PUBKEY_FAIL: u32 = 308;
static RET_EXPORT_ENC_PUBKEY_FAIL: u32 = 309;
static RET_ENC_SIGN_PUBKEY_FAIL: u32 = 310;
static RET_REQ_URL_ROLE_ERR: u32 = 311;
static RET_NOT_FOUND_DEVICE_ERR: u32 = 370;
static RET_DEFAULT_PIN_ERR: u32 = 378;

#[derive(serde::Serialize)]
struct InvokeResponse {
    code: u32,
    message: String,
    data: String,
}

struct AppContext {}

#[tauri::command]
fn login(
    window: Window,
    pin: String,
    app_context: State<'_, AppContext>,
) -> Result<InvokeResponse, String> {
    println!("pin is: {}", pin);
    //判断是否登录
    let mut is_login = IS_LOGIN.lock().unwrap();
    if *is_login {
        println!("login -> 设备已经登录");
        return Ok(InvokeResponse {
            code: 0,
            message: String::from("success"),
            data: String::from(""),
        });
    }

    let mut skf_api = SKF_API.lock().unwrap();
    let mut ret = 0;

    if pin.len() != 6 {
        return Ok(InvokeResponse {
            code: RET_CIPHER_LENGTH_ERROR,
            message: String::from("请输入6位PIN码"),
            data: String::from(""),
        });
    }

    let mut device_names = String::from("");
    let mut name_vec: Vec<String> = Vec::new();
    let mut device_num: u32 = 0;
    ret = skf_api.skf_enum_dev(&mut name_vec, &mut device_num);
    if ret != 0 {
        return Err("枚举设备失败".to_string());
    }
    println!("枚举设备成功");
    println!("device_num: {}", device_num);

    if device_num == 0 {
        // return Err("未发现UEKY".to_string());
        return Ok(InvokeResponse {
            code: RET_NOT_FOUND_DEVICE_ERR,
            message: String::from("未检测到UKEY，请插入UEKY"),
            data: String::from(""),
        });
    } else {
        device_names.push_str(&name_vec.join("||").to_string());
    }
    println!("device names: {}", device_names);
    println!("first device name: {}", name_vec[0]);

    ret = skf_api.skf_connect_dev(&name_vec[0]);
    if ret != 0 {
        println!("连接设备失败, ret: {:x}", ret);
        return Err("连接设备失败".to_string());
    }
    println!("连接设备成功");

    let mut dev_info = DEVINFO::new();
    ret = skf_api.skf_get_dev_info(&mut dev_info);
    if ret != 0 {
        println!("获取设备信息失败, ret: {:x}", ret);
        return Err("获取设备信息失败".to_string());
    }
    println!("获取设备信息成功");

    // let label_name = unsafe { String::from_utf8_unchecked(dev_info.label.to_vec()) };
    let label_name = rust_arr_2_c_char(dev_info.label.to_vec());
    println!("设备标签: {}, length: {}", label_name, label_name.len());

    let app_name_str = String::from("flk_identity_app");
    ret = skf_api.skf_open_application(&app_name_str);
    if ret != 0 {
        println!("打开应用失败, ret: {:x}", ret);
        if ret == skf_err_code::SAR_APPLICATION_NOT_EXISTS {
            return Ok(InvokeResponse {
                code: RET_UKEY_NOT_INIT_ERROR,
                message: String::from("UKEY未初始化"),
                data: String::from(""),
            });
        }
        return Err("打开应用失败".to_string());
    }
    println!("打开应用成功");

    let mut retry_count: u32 = 0;
    ret = skf_api.skf_verify_pin(&pin, &mut retry_count);
    if ret != 0 {
        println!(
            "PIN码验证失败, ret: {:x}, 剩余重试次数: {}",
            ret, retry_count
        );
        if ret == skf_err_code::SAR_PIN_LOCKED {
            return Ok(InvokeResponse {
                code: RET_UKEY_NOT_INIT_ERROR,
                message: String::from("PIN码已被锁定"),
                data: String::from(""),
            });
        }
        if ret == skf_err_code::SAR_PIN_INCORRECT {
            let s = format!("PIN码验证失败, 剩余重试次数: {}", retry_count);
            return Ok(InvokeResponse {
                code: RET_UKEY_NOT_INIT_ERROR,
                message: s.to_string(),
                data: String::from(""),
            });
        }
        return Err("验证PIN码失败".to_string());
    }
    println!("PIN码验证成功");

    let mut user_pin = USER_PIN.lock().unwrap();
    user_pin.clear();
    user_pin.push_str(&pin);

    let mut container_names = String::from("");
    let mut con_name_vec: Vec<String> = Vec::new();
    let mut container_num: u32 = 0;
    ret = skf_api.skf_enum_container(&mut con_name_vec, &mut container_num);
    if ret != 0 {
        return Err("枚举容器失败".to_string());
    }
    println!("枚举容器成功");
    println!("container_num: {}", device_num);

    if container_num == 0 {
        return Ok(InvokeResponse {
            code: RET_UKEY_NOT_INIT_ERROR,
            message: String::from("UKEY未初始化"),
            data: String::from(""),
        });
    } else {
        container_names.push_str(&con_name_vec.join("||").to_string());
        let mut have_container = false;
        for name in con_name_vec {
            if name.as_str() == "Container" {
                have_container = true;
                break;
            }
        }
        if !have_container {
            return Ok(InvokeResponse {
                code: RET_UKEY_ILLEGAL_ERROR,
                message: String::from("非管理员UKEY"),
                data: String::from(""),
            });
        }
    }
    println!("container names: {}", device_names);
    println!("first container name: {}", name_vec[0]);

    let con_name_str = String::from("Container");
    ret = skf_api.skf_open_container(&con_name_str);
    if ret != 0 {
        println!("打开容器失败, ret: {:x}", ret);
        return Err("打开容器失败".to_string());
    }
    println!("打开容器成功");

    *is_login = true;
    if pin.as_str() == "Ae_14e" {
        return Ok(InvokeResponse {
            code: RET_DEFAULT_PIN_ERR,
            message: String::from("登录口令为初始口令"),
            data: String::from(""),
        });
    }
    Ok(InvokeResponse {
        code: 0,
        message: String::from("success"),
        data: String::from(""),
    })
}


#[tauri::command]
fn change_pin(
    window: Window,
    newpin: String,
    skf_context: State<AppContext>,
) -> Result<InvokeResponse, String> {
    println!("change_pin -> newpin: {}", newpin);
    //判断是否登录
    let mut is_login = IS_LOGIN.lock().unwrap();
    if !*is_login {
        println!("change_pin -> 设备未登录");
        return Ok(InvokeResponse {
            code: RET_NOT_LOGIN_ERROR,
            message: String::from("未登录"),
            data: String::from(""),
        });
    }

    let mut ret = 0;

    if newpin.len() != 6 {
        return Ok(InvokeResponse {
            code: RET_CIPHER_LENGTH_ERROR,
            message: String::from("请输入6位新PIN码"),
            data: String::from(""),
        });
    }

    if newpin.as_str() == "Ae_14e" {
        return Ok(InvokeResponse {
            code: RET_DEFAULT_PIN_ERR,
            message: String::from("新口令为默认口令"),
            data: String::from(""),
        });
    }

    let mut oldpin = USER_PIN.lock().unwrap();
    let mut skf_api = SKF_API.lock().unwrap();

    let mut retry_count = 6;
    ret = skf_api.skf_change_pin(&oldpin, &newpin, &mut retry_count);
    if ret != 0 {
        println!(
            "更改PIN码失败, ret: {:x}, 剩余重试次数: {}",
            ret, retry_count
        );
        let s = format!("更改PIN码失败, 剩余重试次数: {}", retry_count);
        return Err(s.to_string());
    }

    oldpin.clear();
    oldpin.push_str(&newpin);

    Ok(InvokeResponse {
        code: 0,
        message: String::from("success"),
        data: String::from(""),
    })
}

// enum AdminLabel {
//     SuperAdmin(u32),
//     SystemAdmin(u32),
//     SecurityAdmin(u32),
//     AuditorAdmin(u32),
// }

// impl AdminLabel {}

fn convert_ukey_label(label: &str) -> u32 {
    if label == "SuperAdmin" {
        return 1;
    }
    if label == "SystemAdmin" {
        return 2;
    }
    if label == "SecurityAdmin" {
        return 3;
    }
    if label == "AuditorAdmin" {
        return 4;
    }
    return 0;
}

#[tauri::command]
fn generate_auth_data(
    window: Window,
    role: u32,
    pin: String,
    app_context: State<'_, AppContext>,
) -> Result<InvokeResponse, String> {
    println!("generate_auth_data -> role: {}, pin: {}", role, pin);
    //判断是否登录
    let mut is_login = IS_LOGIN.lock().unwrap();
    if !*is_login {
        println!("generate_auth_data -> 设备未登录");
        return Ok(InvokeResponse {
            code: RET_NOT_LOGIN_ERROR,
            message: String::from("未登录"),
            data: String::from(""),
        });
    }

    let mut ret = 0;
    let data = pin.as_bytes();
    let mut auth_data = String::from("");
    let mut token_y = String::from("");

    if role < 1 || role > 4 {
        return Err("选择角色不存在".to_string());
    }

    let mut skf_api = SKF_API.lock().unwrap();
    // 检测ukey和选择角色是否匹配
    let mut dev_info = DEVINFO::new();
    ret = skf_api.skf_get_dev_info(&mut dev_info);
    if ret != 0 {
        println!("获取设备信息失败, ret: {:x}", ret);
        return Err("获取设备信息失败".to_string());
    }
    let label_name = rust_arr_2_c_char(dev_info.label.to_vec());
    println!("UKEY角色: {}", label_name);
    if role != convert_ukey_label(&label_name) {
        return Err("UKEY与角色不匹配".to_string());
    }

    //生成时间戳
    let mut time_str = String::from("");
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(n) => time_str = n.as_millis().to_string(),
        Err(_) => return Err("获取时间戳失败".to_string()),
    }
    auth_data.push_str(&time_str);
    auth_data.push_str("||");
    token_y.push_str(&time_str);

    //对口令进行hash计算
    let mut cipher_hash = [0u8; 32];
    ret = skf_api.skf_hash(data, data.len() as u32, &mut cipher_hash, false, None);
    if ret != 0 {
        println!("Hash计算失败");
        return Err("口令Hash计算失败".to_string());
    }
    let hex_cipher_hash = hex::encode(&cipher_hash).to_uppercase();
    println!("hex_cipher_hash: {}", hex_cipher_hash);
    auth_data.push_str(&hex_cipher_hash);
    auth_data.push_str("||");
    token_y.push_str(&hex_cipher_hash);

    //生成随机数
    let mut random = [0u8; 16];
    ret = skf_api.skf_gen_random(&mut random, 16);
    if ret != 0 {
        println!("生成随机数失败, ret: {:x}", ret);
        return Err("生成随机数失败".to_string());
    }
    let hex_random = hex::encode(&random).to_uppercase();
    println!("hex_random: {}", hex_random);
    auth_data.push_str(&hex_random);
    auth_data.push_str("||");
    token_y.push_str(&hex_random);
    println!("token_y: {}", token_y);

    //导出签名公钥
    let mut pubkey = ECCPUBLICKEYBLOB::new();
    ret = skf_api.skf_export_public_key(true, &mut pubkey);
    if ret != 0 {
        println!("导出签名公钥失败, ret: {:x}", ret);
        return Err("导出签名公钥失败".to_string());
    }

    let token_y_byte = token_y.as_bytes();
    let mut token_y_hash = [0u8; 32];
    ret = skf_api.skf_hash(
        token_y_byte,
        token_y_byte.len() as u32,
        &mut token_y_hash,
        true,
        Some(pubkey),
    );
    if ret != 0 {
        println!("token哈希计算失败, ret: {:x}", ret);
        return Err("token哈希计算失败".to_string());
    }
    let hex_token_y_hash = hex::encode(&token_y_hash).to_uppercase();
    println!("token_y_hash: {}", hex_token_y_hash);

    let mut signature = ECCSIGNATUREBLOB::new();
    ret = skf_api.skf_sign(&token_y_hash, 32, &mut signature);
    if ret != 0 {
        println!("token签名计算失败, ret: {:x}", ret);
        return Err("token签名计算失败".to_string());
    }
    let sign_str = signature.to_string();
    println!("sign_str: {}", token_y);
    auth_data.push_str(&sign_str);
    auth_data.push_str("||");

    //导出签名证书
    let mut cert = [0u8; 1024];
    let mut cert_len: u32 = 1024;
    ret = skf_api.skf_export_cert(true, &mut cert, &mut cert_len);
    if ret != 0 {
        println!("导出签名证书失败, ret: {:x}", ret);
        return Err("导出签名证书失败".to_string());
    }
    let cert_str = rust_arr_2_c_char(cert.to_vec());
    println!("cert_str: {}", cert_str);
    auth_data.push_str(&cert_str);
    println!("auth data: {}", auth_data);

    Ok(InvokeResponse {
        code: 0,
        message: String::from("success"),
        data: auth_data,
    })
}

#[tauri::command]
fn logout(window: Window, skf_context: State<AppContext>) -> Result<InvokeResponse, String> {
    //判断是否登录
    let mut is_login = IS_LOGIN.lock().unwrap();
    if !*is_login {
        println!("logout -> 设备未登录");
        return Ok(InvokeResponse {
            code: 0,
            message: String::from("success"),
            data: String::from(""),
        });
    }

    let mut ret = 0;
    let mut skf_api = SKF_API.lock().unwrap();

    ret = skf_api.skf_close_container();
    if ret != 0 {
        println!("关闭容器失败, ret: {:x}", ret);
        // return Err("关闭设备失败".to_string());
    }
    println!("关闭容器成功");

    ret = skf_api.skf_close_application();
    if ret != 0 {
        println!("关闭应用失败, ret: {:x}", ret);
        // return Err("关闭设备失败".to_string());
    }
    println!("关闭应用成功");

    ret = skf_api.skf_disconnect_dev();
    if ret != 0 {
        println!("断开设备连接失败, ret: {:x}", ret);
        return Err("退出登录失败".to_string());
    }
    println!("断开设备连接成功");

    *is_login = false;
    Ok(InvokeResponse {
        code: 0,
        message: String::from("success"),
        data: String::from(""),
    })
}


#[tauri::command]
fn get_mac(window: Window, skf_context: State<AppContext>) -> Result<InvokeResponse, String> {
    let mut mac = String::from("");

    let name = String::from("WLAN");
    match mac_address::mac_address_by_name(&name) {
        Ok(Some(ma)) => {
            println!("WLAN MAC addr: {}", ma);
            // println!("bytes = {:?}", ma.bytes());
            mac.push_str(&ma.to_string());
        }
        Ok(None) => println!("No MAC address found."),
        Err(e) => println!("{:?}", e),
    }

    let name1 = String::from("本地连接");
    match mac_address::mac_address_by_name(&name1) {
        Ok(Some(ma)) => {
            println!("本地连接 MAC addr = {}", ma);
            if mac.len() > 0 {
                mac.push_str(",");
            }
            mac.push_str(&ma.to_string());
        }
        Ok(None) => println!("No MAC address found."),
        Err(e) => println!("{:?}", e),
    }
    let name2 = String::from("以太网");
    match mac_address::mac_address_by_name(&name1) {
        Ok(Some(ma)) => {
            println!("以太网 MAC addr = {}", ma);
            if mac.len() > 0 {
                mac.push_str(",");
            }
            mac.push_str(&ma.to_string());
        }
        Ok(None) => println!("No MAC address found."),
        Err(e) => println!("{:?}", e),
    }

    // match mac_address::get_mac_address() {
    //     Ok(Some(ma)) => {
    //         println!("MAC addr = {}", ma);
    //         println!("bytes = {:?}", ma.bytes());
    //         mac.push_str(&ma.to_string());
    //     }
    //     Ok(None) => println!("No MAC address found."),
    //     Err(e) => println!("{:?}", e),
    // }

    if mac.len() == 0 {
        return Ok(InvokeResponse {
            code: 1,
            message: String::from("获取mac地址失败"),
            data: String::from(""),
        });
    }

    Ok(InvokeResponse {
        code: 0,
        message: String::from("success"),
        data: mac,
    })
}

//全局静态变量
#[macro_use]
extern crate lazy_static;
lazy_static! {
    static ref SKF_API: Mutex<SKFApi> = Mutex::new(SKFApi::new());
    static ref USER_PIN: Mutex<String> = Mutex::new(String::from(""));
    static ref IS_LOGIN: Mutex<bool> = Mutex::new(false);

    // static ref SKF_API: SKFApi = {
    //     let mut skfapi = SKFApi::new();
    //     skfapi
    // };
}

fn main() {
    tauri::Builder::default()
        // This is where you pass in your commands
        // .manage(SKFContext { skf_api: &SKF_API })
        .manage(AppContext {})
        .invoke_handler(tauri::generate_handler![
            login,
            generate_auth_data,
            get_mac,
            change_pin,
            logout
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
