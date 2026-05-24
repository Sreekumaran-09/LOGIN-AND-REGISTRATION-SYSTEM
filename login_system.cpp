#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <algorithm>
#include <limits>
#include <iomanip>
#include <ctime>
#include <cstdint>

using namespace std;

// ═══════════════════════════════════════════════════════
//  SHA-256  (pure C++, no external libraries)
// ═══════════════════════════════════════════════════════
static const uint32_t K256[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,
    0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
    0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,
    0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,
    0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
    0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,
    0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,
    0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
    0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};
#define R(x,n)  (((x)>>(n))|((x)<<(32-(n))))
#define CH(x,y,z) (((x)&(y))^(~(x)&(z)))
#define MJ(x,y,z) (((x)&(y))^((x)&(z))^((y)&(z)))
#define S0(x) (R(x,2) ^R(x,13)^R(x,22))
#define S1(x) (R(x,6) ^R(x,11)^R(x,25))
#define G0(x) (R(x,7) ^R(x,18)^((x)>>3))
#define G1(x) (R(x,17)^R(x,19)^((x)>>10))

string sha256(const string& in) {
    uint32_t h0=0x6a09e667,h1=0xbb67ae85,h2=0x3c6ef372,h3=0xa54ff53a;
    uint32_t h4=0x510e527f,h5=0x9b05688c,h6=0x1f83d9ab,h7=0x5be0cd19;

    vector<uint8_t> m(in.begin(), in.end());
    uint64_t bits = (uint64_t)m.size() * 8;
    m.push_back(0x80);
    while (m.size() % 64 != 56) m.push_back(0);
    for (int i = 7; i >= 0; i--) m.push_back((uint8_t)(bits >> (i*8)));

    for (size_t c = 0; c < m.size(); c += 64) {
        uint32_t w[64];
        for (int i=0;i<16;i++)
            w[i]=((uint32_t)m[c+i*4]<<24)|((uint32_t)m[c+i*4+1]<<16)
                |((uint32_t)m[c+i*4+2]<<8)|(uint32_t)m[c+i*4+3];
        for (int i=16;i<64;i++) w[i]=G1(w[i-2])+w[i-7]+G0(w[i-15])+w[i-16];
        uint32_t a=h0,b=h1,cc=h2,d=h3,e=h4,f=h5,g=h6,h=h7;
        for (int i=0;i<64;i++){
            uint32_t t1=h+S1(e)+CH(e,f,g)+K256[i]+w[i];
            uint32_t t2=S0(a)+MJ(a,b,cc);
            h=g;g=f;f=e;e=d+t1;d=cc;cc=b;b=a;a=t1+t2;
        }
        h0+=a;h1+=b;h2+=cc;h3+=d;h4+=e;h5+=f;h6+=g;h7+=h;
    }
    char buf[65];
    snprintf(buf,65,"%08x%08x%08x%08x%08x%08x%08x%08x",
             h0,h1,h2,h3,h4,h5,h6,h7);
    return string(buf);
}

// ═══════════════════════════════════════════════════════
//  Constants
// ═══════════════════════════════════════════════════════
const string DB_FILE      = "users.dat";
const string LOG_FILE     = "auth.log";
const int    MIN_PASS_LEN = 6;
const int    MIN_USER_LEN = 3;
const int    MAX_ATTEMPTS = 3;

// ═══════════════════════════════════════════════════════
//  Logging
// ═══════════════════════════════════════════════════════
void writeLog(const string& event) {
    ofstream log(LOG_FILE, ios::app);
    if (!log) return;
    time_t now = time(nullptr);
    char tb[20];
    strftime(tb, sizeof(tb), "%Y-%m-%d %H:%M:%S", localtime(&now));
    log << "[" << tb << "] " << event << "\n";
}

// ═══════════════════════════════════════════════════════
//  Display helpers
// ═══════════════════════════════════════════════════════
void printLine(char ch='-', int w=58){ cout << string(w,ch) << "\n"; }

void printBanner(){
    printLine('=');
    cout << "        L O G I N  &  R E G I S T R A T I O N\n";
    cout << "            Secure | File-based | SHA-256\n";
    printLine('=');
}

void ok (const string& m){ cout << "\n  [ OK ]  " << m << "\n\n"; }
void err(const string& m){ cout << "\n  [FAIL]  " << m << "\n\n"; }
void inf(const string& m){ cout <<   "  [INFO]  " << m << "\n"; }

// ═══════════════════════════════════════════════════════
//  Input helpers
// ═══════════════════════════════════════════════════════
void flush(){ cin.ignore(numeric_limits<streamsize>::max(),'\n'); }

string prompt(const string& label){
    cout << "  " << label;
    string v; cin >> v; flush();
    return v;
}

// ═══════════════════════════════════════════════════════
//  Validation
// ═══════════════════════════════════════════════════════
bool isAlnum_(const string& s){
    for(char c:s) if(!isalnum(c)&&c!='_') return false;
    return true;
}

// Returns "" if valid, else error string
string checkUser(const string& u){
    if((int)u.size()<MIN_USER_LEN)
        return "Username must be at least "+to_string(MIN_USER_LEN)+" characters.";
    if(!isAlnum_(u))
        return "Username: only letters, digits and underscores allowed.";
    return "";
}

string checkPass(const string& p){
    if((int)p.size()<MIN_PASS_LEN)
        return "Password must be at least "+to_string(MIN_PASS_LEN)+" characters.";
    bool up=false,lo=false,di=false;
    for(char c:p){ if(isupper(c))up=true; if(islower(c))lo=true; if(isdigit(c))di=true; }
    if(!up) return "Password needs at least one UPPERCASE letter.";
    if(!lo) return "Password needs at least one lowercase letter.";
    if(!di) return "Password needs at least one digit (0-9).";
    return "";
}

// ═══════════════════════════════════════════════════════
//  Database  —  CSV: username , salt , sha256hash
// ═══════════════════════════════════════════════════════
struct User { string name, salt, hash; };

vector<User> loadDB(){
    vector<User> db;
    ifstream f(DB_FILE);
    string line;
    while(getline(f,line)){
        if(line.empty()||line[0]=='#') continue;
        istringstream ss(line);
        User u;
        if(getline(ss,u.name,',')&&getline(ss,u.salt,',')&&getline(ss,u.hash,','))
            db.push_back(u);
    }
    return db;
}

bool appendUser(const User& u){
    // create header on first write
    {
        ifstream chk(DB_FILE);
        if(!chk.good()){
            ofstream hdr(DB_FILE);
            hdr << "# username,salt,sha256(salt+password)\n";
        }
    }
    ofstream f(DB_FILE, ios::app);
    if(!f) return false;
    f << u.name << "," << u.salt << "," << u.hash << "\n";
    return true;
}

bool exists(const string& name, const vector<User>& db){
    string lo=name;
    transform(lo.begin(),lo.end(),lo.begin(),::tolower);
    for(auto& u:db){
        string ul=u.name;
        transform(ul.begin(),ul.end(),ul.begin(),::tolower);
        if(ul==lo) return true;
    }
    return false;
}

string makeSalt(const string& name){
    return to_string(time(nullptr))+"_"+to_string(name.size());
}

// ═══════════════════════════════════════════════════════
//  REGISTRATION
// ═══════════════════════════════════════════════════════
void registerUser(){
    cout << "\n"; printLine();
    cout << "  REGISTER A NEW ACCOUNT\n"; printLine();

    string uname = prompt("Username       : ");

    string ue = checkUser(uname);
    if(!ue.empty()){ err(ue); return; }

    auto db = loadDB();
    if(exists(uname,db)){
        err("Username '"+uname+"' is already taken. Choose another.");
        writeLog("REGISTER_FAIL|duplicate|"+uname);
        return;
    }

    cout << "\n  Password rules:\n"
         << "  * Min " << MIN_PASS_LEN << " characters\n"
         << "  * At least one uppercase letter  (A-Z)\n"
         << "  * At least one lowercase letter  (a-z)\n"
         << "  * At least one digit             (0-9)\n\n";

    string pass    = prompt("Password       : ");
    string pe = checkPass(pass);
    if(!pe.empty()){ err(pe); return; }

    string confirm = prompt("Confirm passwd : ");
    if(pass != confirm){
        err("Passwords do not match. Registration cancelled.");
        writeLog("REGISTER_FAIL|mismatch|"+uname);
        return;
    }

    string salt = makeSalt(uname);
    string hash = sha256(salt + pass);

    if(!appendUser({uname, salt, hash})){
        err("Database write failed. Check file permissions.");
        return;
    }

    ok("Account created for '"+uname+"'. You may now log in.");
    writeLog("REGISTER_OK|"+uname);
}

// ═══════════════════════════════════════════════════════
//  LOGIN
// ═══════════════════════════════════════════════════════
void loginUser(){
    cout << "\n"; printLine();
    cout << "  USER LOGIN\n"; printLine();

    auto db = loadDB();
    if(db.empty()){ inf("No accounts yet. Please register first.\n"); return; }

    for(int attempt=1; attempt<=MAX_ATTEMPTS; attempt++){
        cout << "  Attempt " << attempt << " / " << MAX_ATTEMPTS << "\n";
        string uname = prompt("Username : ");
        string pass  = prompt("Password : ");

        string lo=uname;
        transform(lo.begin(),lo.end(),lo.begin(),::tolower);

        bool found=false;
        for(auto& u:db){
            string ul=u.name;
            transform(ul.begin(),ul.end(),ul.begin(),::tolower);
            if(ul==lo){
                found=true;
                if(sha256(u.salt+pass)==u.hash){
                    ok("Welcome back, "+u.name+"!  Login successful.");
                    writeLog("LOGIN_OK|"+u.name);
                    return;
                }
                break;
            }
        }

        int left = MAX_ATTEMPTS-attempt;
        if(!found) err("Username not found.");
        else       err("Wrong password. "+to_string(left)+" attempt(s) left.");
        writeLog("LOGIN_FAIL|attempt"+to_string(attempt)+"|"+uname);
    }

    err("Too many failed attempts. Access denied.");
    writeLog("LOGIN_BLOCKED|"+to_string(MAX_ATTEMPTS)+" attempts exhausted.");
}

// ═══════════════════════════════════════════════════════
//  LIST USERS  (shows masked hash — no plain passwords)
// ═══════════════════════════════════════════════════════
void listUsers(){
    cout << "\n"; printLine();
    cout << "  REGISTERED USERS\n"; printLine();

    auto db = loadDB();
    if(db.empty()){ inf("No users registered yet.\n"); return; }

    cout << left << setw(5) <<"No." << setw(20) <<"Username"
         << "SHA-256 (first 20 chars)\n";
    printLine('-',50);
    int i=1;
    for(auto& u:db)
        cout << left << setw(5) << i++ << setw(20) << u.name
             << u.hash.substr(0,20) << "...\n";
    cout << "\n  Total: " << db.size() << " account(s)\n\n";
}

// ═══════════════════════════════════════════════════════
//  MAIN MENU
// ═══════════════════════════════════════════════════════
int main(){
    printBanner();

    while(true){
        cout << "\n  MAIN MENU\n";
        printLine('-',30);
        cout << "  1. Register new account\n"
             << "  2. Login\n"
             << "  3. View registered users\n"
             << "  4. Exit\n";
        printLine('-',30);

        string ch = prompt("Choice : ");

        if      (ch=="1") registerUser();
        else if (ch=="2") loginUser();
        else if (ch=="3") listUsers();
        else if (ch=="4"){ cout<<"\n  Goodbye!\n\n"; break; }
        else err("Invalid option. Enter 1, 2, 3, or 4.");
    }
    return 0;
}
