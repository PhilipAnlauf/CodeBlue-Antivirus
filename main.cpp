#include <iostream>
#include <fstream>
#include <string>
#include <filesystem>
#include <thread>
#include <vector>

using namespace std;

//========================/Lists/========================//
//Lists held as char pointer arrays, noticeably faster performance.
const char* redTeamStrings[] = 
{
    "red team", "r3d team", "red t3am", "r3d t3am", "red_team", "r3d_t3am", 
    "red-team", "r3d-team", "red.team", "r3d.team", "red@team", "r3d@team", 
    "red&team", "r3d&team", "r3d t34m", "red-te4m", "r3d te@m", "r3d t3@m", 
    "red t3@m", "red_te@m", "r3d_te@m", "r3d-te@m", "red.team!", "r3d.team!", 
    "red@team!", "r3d@team!", "red!team", "r3d!team", "red team!", "r3d team!", 
    "red_team1", "r3d_team2", "red_team3", "redteam", "r3dteam", "redt3am",
    "redte4m", "r3dt3am", "r3dte4m", "redt34m", "Red Team", "R3d Team", 
    "Red T3am", "R3d T3am", "Red_Team", "R3d_Team", "Red-Team", "R3d-Team", 
    "Red.Team", "R3d.Team", "Red@Team", "R3d@Team", "Red&Team", "R3d&Team", 
    "R3d T34m", "Red-Te4m", "R3d Te@m", "R3d T3@m", "R3DTE4M", "REDT34M",
    "Red T3@m", "Red_Te@m", "R3d_Te@m", "R3d-Te@m", "Red.Team!", "R3d.Team!", 
    "Red@Team!", "R3d@Team!", "Red!Team", "R3d!Team", "Red Team!", "R3d Team!", 
    "Red_Team1", "R3d_Team2", "Red_Team3", "RedTeam", "R3dTeam", "RedT3am",
    "RedTe4m", "R3dT3am", "R3dTe4m", "RedT34m", "RED TEAM", "R3D TEAM", 
    "RED T3AM", "R3D T3AM", "RED_TEAM", "R3D_TEAM", "RED-TEAM", "R3D-TEAM", 
    "RED.TEAM", "R3D.TEAM", "RED@TEAM", "R3D@TEAM", "RED&TEAM", "R3D&TEAM", 
    "R3D T34M", "RED-TE4M", "R3D TE@M", "R3D T3@M", "RED T3@M", "RED_TE@M", 
    "R3D_TE@M", "R3D-TE@M", "RED.TEAM!", "R3D.TEAM!", "RED@TEAM!", "R3D@TEAM!", 
    "RED!TEAM", "R3D!TEAM", "RED TEAM!", "R3D TEAM!", "RED_TEAM1", "R3D_TEAM2", 
    "RED_TEAM3", "REDTEAM", "R3DTEAM", "REDT3AM", "REDTE4M", "R3DT3AM"
};

const char* keywordList[] = 
{
    "keylogger", "keylog", "keyboard_capture", "keystroke", "password_stealer", "credential_dump",
    "clipboard_logger", "clipboard_monitor", "screenshot_capture", "export_to_ip", "data_exfiltration",
    "remote_server", "command_and_control", "c2_server", "malicious_ip", "hardcoded_ip",
    "dns_tunnel", "dynamic_dns", "tcp_connection", "network_activity", "outbound_traffic",
    "unauthorized_access", "backdoor", "reverse_shell", "persistence", "registry_modification",
    "startup_injection", "task_scheduling", "autorun", "self_replicate", "worm", "dropper",
    "payload_delivery", "re_download", "auto_update", "file_encryption", "ransom_demand",
    "browser_injection", "network_sniffer", "encrypted_traffic", "process_injection", "dll_injection",
    "code_injection", "powershell_execution", "cmd.exe", "bat_file", "vbs_script", "fileless_malware",
    "memory_injection", "obfuscation", "base64_decode", "xor_encryption", "sandbox_detection",
    "vm_detection", "anti_debug", "packer", "cryptor", "malware", "virus", "trojan", "spyware",
    "phishing_payload", "cookie_exfiltration", "token_theft", "usb_infection", "email_attachment",
    "binary_patching", "code_tampering", "spoofing", "proxy_execution", "lateral_movement", "rootkit",
    "bootkit", "uefi_malware", "Keylogger", "Keylog", "Keyboard_Capture", "Keystroke", "Password_Stealer",
    "Clipboard_Logger", "Clipboard_Monitor", "Screenshot_Capture", "Export_To_IP", "Data_Exfiltration",
    "Remote_Server", "Command_And_Control", "C2_Server", "Malicious_IP", "Hardcoded_IP",
    "DNS_Tunnel", "Dynamic_DNS", "TCP_Connection", "Network_Activity", "Outbound_Traffic",
    "Unauthorized_Access", "Backdoor", "Reverse_Shell", "Persistence", "Registry_Modification",
    "Startup_Injection", "Task_Scheduling", "Autorun", "Self_Replicate", "Worm", "Dropper",
    "Payload_Delivery", "Re_Download", "Auto_Update", "File_Encryption", "Ransom_Demand",
    "Browser_Injection", "Network_Sniffer", "Encrypted_Traffic", "Process_Injection", "DLL_Injection",
    "Code_Injection", "Powershell_Execution", "CMD.exe", "BAT_File", "VBS_Script", "Fileless_Malware",
    "Memory_Injection", "Obfuscation", "Base64_Decode", "XOR_Encryption", "Sandbox_Detection",
    "VM_Detection", "Anti_Debug", "Packer", "Cryptor", "Malware", "Virus", "Trojan", "Spyware",
    "Phishing_Payload", "Cookie_Exfiltration", "Token_Theft", "USB_Infection", "Email_Attachment",
    "Binary_Patching", "Code_Tampering", "Spoofing", "Proxy_Execution", "Lateral_Movement", "Rootkit",
    "Bootkit", "UEFI_Malware", "KEYLOGGER", "KEYLOG", "KEYBOARD_CAPTURE", "KEYSTROKE", 
    "PASSWORD_STEALER", "CREDENTIAL_DUMP", "CLIPBOARD_LOGGER", "CLIPBOARD_MONITOR", "SCREENSHOT_CAPTURE",
    "EXPORT_TO_IP", "DATA_EXFILTRATION", "REMOTE_SERVER", "COMMAND_AND_CONTROL", "C2_SERVER", 
    "MALICIOUS_IP", "HARDCODED_IP", "DNS_TUNNEL", "DYNAMIC_DNS", "TCP_CONNECTION", "NETWORK_ACTIVITY",
    "OUTBOUND_TRAFFIC", "UNAUTHORIZED_ACCESS", "BACKDOOR", "REVERSE_SHELL", "PERSISTENCE",
    "REGISTRY_MODIFICATION", "STARTUP_INJECTION", "TASK_SCHEDULING", "AUTORUN", "SELF_REPLICATE",
    "WORM", "DROPPER", "PAYLOAD_DELIVERY", "RE_DOWNLOAD", "AUTO_UPDATE", "FILE_ENCRYPTION",
    "RANSOM_DEMAND", "BROWSER_INJECTION", "NETWORK_SNIFFER", "ENCRYPTED_TRAFFIC", "PROCESS_INJECTION",
    "DLL_INJECTION", "CODE_INJECTION", "POWERSHELL_EXECUTION", "CMD.EXE", "BAT_FILE", "VBS_SCRIPT",
    "FILELESS_MALWARE", "MEMORY_INJECTION", "OBFUSCATION", "BASE64_DECODE", "XOR_ENCRYPTION",
    "SANDBOX_DETECTION", "VM_DETECTION", "ANTI_DEBUG", "PACKER", "CRYPTOR", "MALWARE", "VIRUS",
    "TROJAN", "SPYWARE", "PHISHING_PAYLOAD", "COOKIE_EXFILTRATION", "TOKEN_THEFT", "USB_INFECTION",
    "EMAIL_ATTACHMENT", "BINARY_PATCHING", "CODE_TAMPERING", "SPOOFING", "PROXY_EXECUTION",
    "LATERAL_MOVEMENT", "ROOTKIT", "BOOTKIT", "UEFI_MALWARE", "Credential_Dump"

};

const char* keywordListCharacters[] =
{
    "$andbox_detection", "$creen$hot_capture", "$elf_replicate", "$poofing", "$pyware",
    "$tartup_injection", "0bfuscati0n", "0utb0und_traffic", "3mail_attachm3nt", "3ncrypt3d_traffic",
    "3xport_to_ip", "4nti_debug", "4uto_upd4te", "4utorun", "5andbox_detection", "5creen5hot_capture",
    "5elf_replicate", "5poofing", "5pyware", "5tartup_injection", "@nti_debug", "@uto_upd@te",
    "@utorun", "ant!_debug", "ant1_debug", "anti_d3bug", "anti_debug", "aut0_update", "aut0run",
    "auto_updat3", "auto_update", "autorun", "b!nary_patch!ng", "b00tkit", "b1nary_patch1ng",
    "b4ckdoor", "b4se64_decode", "b4t_file", "b@ckdoor", "b@se64_decode", "b@t_file",
    "ba$e64_decode", "ba5e64_decode", "backd00r", "backdoor", "bas364_d3cod3", "base64_dec0de",
    "base64_decode", "bat_f!le", "bat_f1le", "bat_fil3", "bat_file", "bin4ry_p4tching", "bin@ry_p@tching",
    "binary_patching", "bootk!t", "bootk1t", "bootkit", "br0wser_injecti0n", "brow$er_injection",
    "brow5er_injection", "brows3r_inj3ction", "browser_!nject!on", "browser_1nject1on",
    "browser_injection", "c00kie_exfiltrati0n", "c0de_injecti0n", "c0de_tampering",
    "c0mmand_and_c0ntr0l", "c2_$erver", "c2_5erver", "c2_s3rv3r", "c2_server", "cl!pboard_logger",
    "cl!pboard_mon!tor", "cl1pboard_logger", "cl1pboard_mon1tor", "clipb0ard_l0gger",
    "clipb0ard_m0nit0r", "clipbo4rd_logger", "clipbo4rd_monitor", "clipbo@rd_logger",
    "clipbo@rd_monitor", "clipboard_logg3r", "clipboard_logger", "clipboard_monitor", "cmd.3x3",
    "cmd.exe", "cod3_inj3ction", "cod3_tamp3ring", "code_!nject!on", "code_1nject1on",
    "code_injection", "code_t4mpering", "code_t@mpering", "code_tamper!ng", "code_tamper1ng",
    "code_tampering", "comm4nd_4nd_control", "comm@nd_@nd_control", "command_and_control",
    "cook!e_exf!ltrat!on", "cook1e_exf1ltrat1on", "cooki3_3xfiltration", "cookie_exfiltr4tion",
    "cookie_exfiltr@tion", "cookie_exfiltration", "cr3d3ntial_dump", "credent!al_dump",
    "credent1al_dump", "credenti4l_dump", "credenti@l_dump", "credential_dump", "crypt0r", "cryptor",
    "d4t4_exfiltr4tion", "d@t@_exfiltr@tion", "data_3xfiltration", "data_exf!ltrat!on", "data_exf1ltrat1on",
    "data_exfiltrati0n", "data_exfiltration", "dll_!nject!on", "dll_1nject1on", "dll_inj3ction", "dll_injecti0n",
    "dll_injection", "dn$_tunnel", "dn5_tunnel", "dns_tunn3l", "dns_tunnel", "dr0pper", "dropp3r",
    "dropper", "dyn4mic_dns", "dyn@mic_dns", "dynam!c_dns", "dynam1c_dns", "dynamic_dn$",
    "dynamic_dn5", "dynamic_dns", "em4il_4tt4chment", "em@il_@tt@chment", "ema!l_attachment",
    "ema1l_attachment", "email_attachment", "encrypted_tr4ffic", "encrypted_tr@ffic",
    "encrypted_traff!c", "encrypted_traff1c", "encrypted_traffic", "exp0rt_t0_ip", "export_to_!p",
    "export_to_1p", "export_to_ip", "f!le_encrypt!on", "f!leless_malware", "f1le_encrypt1on",
    "f1leless_malware", "fil3_3ncryption", "fil3l3ss_malwar3", "file_encrypti0n", "file_encryption",
    "filele$$_malware", "filele55_malware", "fileless_m4lw4re", "fileless_m@lw@re", "fileless_malware",
    "h4rdcoded_ip", "h@rdcoded_ip", "hardc0ded_ip", "hardcod3d_ip", "hardcoded_!p",
    "hardcoded_1p", "hardcoded_ip", "k3yboard_captur3", "k3ylog", "k3ylogg3r", "k3ystrok3",
    "key$troke", "key5troke", "keyb0ard_capture", "keybo4rd_c4pture", "keybo@rd_c@pture",
    "keyboard_capture", "keyl0g", "keyl0gger", "keylog", "keylogger", "keystr0ke", "keystroke",
    "l4ter4l_movement", "l@ter@l_movement", "lat3ral_mov3m3nt", "lateral_m0vement",
    "lateral_movement", "m3mory_inj3ction", "m4licious_ip", "m4lw4re", "m@licious_ip", "m@lw@re",
    "mal!c!ous_!p", "mal1c1ous_1p", "malici0us_ip", "maliciou$_ip", "maliciou5_ip", "malicious_ip",
    "malwar3", "malware", "mem0ry_injecti0n", "memory_!nject!on", "memory_1nject1on",
    "memory_injection", "n3twork_activity", "n3twork_sniff3r", "netw0rk_activity", "netw0rk_sniffer",
    "network_$niffer", "network_4ctivity", "network_5niffer", "network_@ctivity", "network_act!v!ty",
    "network_act1v1ty", "network_activity", "network_sn!ffer", "network_sn1ffer", "network_sniffer",
    "obfu$cation", "obfu5cation", "obfusc4tion", "obfusc@tion", "obfuscat!on", "obfuscat1on",
    "obfuscation", "outbound_tr4ffic", "outbound_tr@ffic", "outbound_traff!c", "outbound_traff1c",
    "outbound_traffic", "p0wershell_executi0n", "p3rsist3nc3", "p4cker", "p4ssword_ste4ler",
    "p4ylo4d_delivery", "p@cker", "p@ssword_ste@ler", "p@ylo@d_delivery", "pa$$word_$tealer",
    "pa55word_5tealer", "pack3r", "packer", "passw0rd_stealer", "password_st3al3r",
    "password_stealer", "payl0ad_delivery", "payload_d3liv3ry", "payload_del!very", "payload_del1very",
    "payload_delivery", "per$i$tence", "per5i5tence", "pers!stence", "pers1stence", "persistence",
    "ph!sh!ng_payload", "ph1sh1ng_payload", "phi$hing_payload", "phi5hing_payload",
    "phishing_p4ylo4d", "phishing_p@ylo@d", "phishing_payl0ad", "phishing_payload",
    "pow3rsh3ll_3x3cution", "power$hell_execution", "power5hell_execution", "powershell_execut!on",
    "powershell_execut1on", "powershell_execution", "pr0cess_injecti0n", "pr0xy_executi0n",
    "proc3ss_inj3ction", "proce$$_injection", "proce55_injection", "process_!nject!on",
    "process_1nject1on", "process_injection", "proxy_3x3cution", "proxy_execut!on", "proxy_execut1on",
    "proxy_execution", "r00tkit", "r3_download", "r3gistry_modification", "r3mot3_s3rv3r",
    "r3v3rs3_sh3ll", "r4nsom_dem4nd", "r@nsom_dem@nd", "ran$om_demand",
    "ran5om_demand", "rans0m_demand", "ransom_d3mand", "ransom_demand", "re_d0wnl0ad",
    "re_downlo4d", "re_downlo@d", "re_download", "reg!stry_mod!f!cat!on", "reg1stry_mod1f1cat1on",
    "regi$try_modification", "regi5try_modification", "registry_m0dificati0n", "registry_modific4tion",
    "registry_modific@tion", "registry_modification", "rem0te_server", "remote_$erver", "remote_5erver",
    "remote_server", "rever$e_$hell", "rever5e_5hell", "reverse_shell", "rootk!t", "rootk1t", "rootkit",
    "s3lf_r3plicat3", "s4ndbox_detection", "s@ndbox_detection", "sandb0x_detecti0n",
    "sandbox_d3t3ction", "sandbox_detect!on", "sandbox_detect1on", "sandbox_detection",
    "scr33nshot_captur3", "screensh0t_capture", "screenshot_c4pture", "screenshot_c@pture",
    "screenshot_capture", "self_repl!cate", "self_repl1cate", "self_replic4te", "self_replic@te",
    "self_replicate", "sp00fing", "spoof!ng", "spoof1ng", "spoofing", "spyw4re", "spyw@re", "spywar3",
    "spyware", "st4rtup_injection", "st@rtup_injection", "startup_!nject!on", "startup_1nject1on",
    "startup_inj3ction", "startup_injecti0n", "startup_injection", "t0ken_theft", "t4sk_scheduling",
    "t@sk_scheduling", "ta$k_$cheduling", "ta5k_5cheduling", "task_sch3duling", "task_schedul!ng",
    "task_schedul1ng", "task_scheduling", "tcp_c0nnecti0n", "tcp_conn3ction", "tcp_connect!on",
    "tcp_connect1on", "tcp_connection", "tok3n_th3ft", "token_theft", "tr0jan", "troj4n", "troj@n", "trojan",
    "u$b_infection", "u3fi_malwar3", "u5b_infection", "uef!_malware", "uef1_malware", "uefi_m4lw4re",
    "uefi_m@lw@re", "uefi_malware", "un4uthorized_4ccess", "un@uthorized_@ccess",
    "unauth0rized_access", "unauthor!zed_access", "unauthor1zed_access", "unauthoriz3d_acc3ss",
    "unauthorized_acce$$", "unauthorized_acce55", "unauthorized_access", "usb_!nfect!on",
    "usb_1nfect1on", "usb_inf3ction", "usb_infecti0n", "usb_infection", "v!rus", "v1rus", "vb$_$cript",
    "vb5_5cript", "vbs_scr!pt", "vbs_scr1pt", "vbs_script", "viru$", "viru5", "virus", "vm_d3t3ction",
    "vm_detect!on", "vm_detect1on", "vm_detecti0n", "vm_detection", "w0rm", "worm", "x0r_encrypti0n",
    "xor_3ncryption", "xor_encrypt!on", "xor_encrypt1on", "xor_encryption"
};

//=======================================================//

//Sizes of the arrays declared as seperate variables for readability, no huge time or memory save.
const int RED_TEAM_STRING_SIZE = sizeof(redTeamStrings) / sizeof(redTeamStrings[0]);
const int KEYWORD_LIST_SIZE = sizeof(keywordList) / sizeof(keywordList[0]);
const int KEYWORD_LIST_CHARACTER_SIZE = sizeof(keywordListCharacters) / sizeof(keywordListCharacters[0]);

bool isSus;

const string executableList[] = {".bin", "", ".elf", ".sh", ".exe", ".deb", ".out"};

const bool isExecutable(const filesystem::path& filePath)
{
    string fileType = filePath.extension().string();

    for(int i = 0; i < (sizeof(executableList)/sizeof(executableList[0])); i++)
    {
        if(executableList[i] == fileType)
        {
            return true;
        }
    }

    return false;
}

const vector<string> stringDump(const string& filename)
{
    string hold = ""; 
    vector<string> brokeUpStringDump;   
    
    ifstream file(filename, ios::binary);
    if(!file)
    {
        cout << "Failed to open file: " << filename << endl;
        return brokeUpStringDump;
    }
    
    char hexDec;

    while(file.get(hexDec))
    {
        if(isprint(static_cast<unsigned char>(hexDec)))
        {
            hold = hold+hexDec;
        }
        else
        {
            //hold = hold+".";
        }
    }

    istringstream iss(hold);
    string word;
    while (iss >> word) {
        brokeUpStringDump.push_back(word);
    }

    file.close();

    return brokeUpStringDump;
}

const void stringAnalyze(const string& heldString)
{
    for(int i = 0; i < KEYWORD_LIST_SIZE; i++)
    {
        if (heldString.find(keywordListCharacters[i]) != string::npos && !isSus)
        {
            cout << "Suspicous word found: " << keywordList[i] << endl;
            isSus = true;
            goto done;
        }
    }

    for(int i = 0; i < KEYWORD_LIST_CHARACTER_SIZE; i++)
    {
        if (heldString.find(keywordListCharacters[i]) != string::npos && !isSus)
        {
            cout << "Suspicous word found: " << keywordListCharacters[i] << endl;
            isSus = true;
            goto done;
        }
    }  

    for(int i = 0; i < RED_TEAM_STRING_SIZE; i++)
    {
        if (heldString.find(redTeamStrings[i]) != string::npos && !isSus)
        {
            cout << "Red team word found: " << redTeamStrings[i] << endl;
            isSus = true;
            goto done;
        }
    }

    done:
        return;
}

const void checkIfSuspectFile(const string& filePathIN)
{
    isSus = false;

    vector<string> heldStringVector = stringDump(filePathIN);

    string firstHalfAssembled = "";
    string secondHalfAssembled = "";

    for(int i = 0; i < heldStringVector.size()/2; i++)
    {
        firstHalfAssembled = firstHalfAssembled+heldStringVector[i];
    }

    for(int i = heldStringVector.size()/2; i < heldStringVector.size(); i++)
    {
        secondHalfAssembled = secondHalfAssembled+heldStringVector[i];
    }


    thread forwardAnalyze(stringAnalyze, firstHalfAssembled);
    thread backwardAnalyze(stringAnalyze, secondHalfAssembled);

    forwardAnalyze.join();
    backwardAnalyze.join();

    if(isSus)
    {
        cout << "This file is suspicous; " << filePathIN << endl;
    }
}

const int getFileSize(const string& filePath)
{
    streampos begin, end;
    ifstream myfile (filePath, ios::binary);
    begin = myfile.tellg();
    myfile.seekg(0, ios::end);
    end = myfile.tellg();
    myfile.close();
    return (end-begin);
}

//==================

const void directroyLoop(const string& parentDirectory)
{
    for (const auto & entry : filesystem::directory_iterator(parentDirectory)) 
    { 
        try
        {

            if (entry.is_regular_file() && getFileSize(entry.path()) <= 1000000 && isExecutable(entry.path())) 
            {
                checkIfSuspectFile(entry.path());
            }
            else if(!entry.is_regular_file() && entry.path() != "//bin" && entry.path() != "//sbin" && entry.path() != "//usr/bin" && entry.path() != "//usr/sbin" && entry.path() != "//lib" && entry.path() != "//usr/lib" && entry.path() != "//etc" && entry.path() != "//boot" && entry.path() != "//sys" && entry.path() != "//var/log" && entry.path() != "//var/lib" && entry.path() != "//dev" && entry.path() != "//proc")
            {
                directroyLoop(entry.path());
            }
            else
            {
                //cout << "File is too big or an unneeded folder" << endl;
            }

        }
        catch(const std::exception& e)
        {
           // cerr << e.what() << '\n';
        }
        
    }
}

int main()
{
    cout << "CPU Has: " << thread::hardware_concurrency() << " threads." << endl;
    cout << "Beginning search." << endl;
    thread searchman1(directroyLoop, "/");
    
    searchman1.join();

    return 0;
}

//TODO:
    //Revamp the multithreading for the string dump analyzing.
    //instead of going forward -> and <- backward make both go forward ->
    //and make the total size that each thread has to search be divisible
    //by the number of available threads, 0->end, 0->1/2 1/2->end, 0->1/3 1/3->2/3 2/3->end, etc.
    //                                   1 thread    2 threads           3 threads
    //acount for needing a thread for main OS operation and secondary threads for other antivirus features
    //perhaps only max out at three threads