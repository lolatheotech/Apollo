#include <algorithm>
#include <cassert>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
namespace fs=std::filesystem;
namespace SimpleWeb { enum class StatusCode {success_ok=200,client_error_bad_request=400,client_error_unauthorized=401,client_error_forbidden=403,server_error_internal_server_error=500}; }
namespace PERM { constexpr int _allow_view=1,file_upload=2; }
struct Client {std::string uuid="owner";int perm=3;};
struct Content {std::string value;std::string string() const{return value;}};
using Args=std::unordered_map<std::string,std::string>;
struct Request {Client client;Args args;Content content;Args parse_query_string(){return args;}};
struct Response {SimpleWeb::StatusCode code;std::string id,state,failure;};
using req_https_t=std::shared_ptr<Request>;using resp_https_t=std::shared_ptr<Response>;
struct SunshineHTTPS{};
template<class T> void print_req(req_https_t){}
Client* get_verified_cert(req_https_t r){return &r->client;}
std::string get_arg(const Args& a,const std::string& k,const std::string& d){auto i=a.find(k);return i==a.end()?d:i->second;}
bool lola_active_client(Client*){return true;}
void lola_file_reply(resp_https_t r,SimpleWeb::StatusCode c,const std::string&i,const std::string&s,const std::string&f={}){r->code=c;r->id=i;r->state=s;r->failure=f;}
namespace crypto {std::string hash(const std::string& s){return s;}}
namespace util {struct Hex{std::string s;std::string to_string(){return s;}};Hex hex(std::string s){return {s};}}
fs::path root;
namespace platf {fs::path appdata(){return root;}}
#define BOOST_LOG(level) std::ostringstream{}
enum class lola_scan_result {clean,malware,error};
lola_scan_result scan_result=lola_scan_result::clean;
lola_scan_result lola_scan_payload(std::string_view){return scan_result;}
std::string lola_sha256(std::string_view content){return content=="DATA"?std::string(64,'a'):std::string(64,'b');}
// The actual production reservation structure, validation, receive and cancel
// handlers are extracted verbatim by run-lola-transfer-contract.ps1 below.
// TLS authentication and malware-provider integration are NOT mocked proofs.
#include "lola-transfer-under-test.inc"
int cases=0;
void check(bool ok,const char* description){if(!ok){std::cerr<<"FAIL "<<description<<"\n";std::exit(1);}++cases;}
req_https_t request(std::string id){auto r=std::make_shared<Request>();r->args={{"transferId",id},{"sessionId","session"},{"fileName","test.txt"},{"sha256",std::string(64,'a')},{"consent","true"},{"length","4"}};return r;}
resp_https_t prepare(req_https_t q){auto r=std::make_shared<Response>();receiveLolaFile(r,q,true);return r;}
resp_https_t upload(req_https_t q){auto r=std::make_shared<Response>();q->content.value="DATA";receiveLolaFile(r,q,false);return r;}
resp_https_t cancel(req_https_t q){auto r=std::make_shared<Response>();cancelLolaFile(r,q);return r;}
int main(int argc,char**argv){
 if(argc!=2)return 2;root=argv[1];if(fs::exists(root))return 2;fs::create_directories(root);
 auto q=request("early");check(prepare(q)->state=="Authorized","prepare");
 check(!fs::exists(root/"lola-file-transfer-quarantine"/"owner"/"early"),"no partial before body");
 check(cancel(q)->state=="Cancelled","early acknowledgement");
 check(upload(q)->failure=="unknown_transfer","buffered late body cannot resurrect cancelled reservation");
 check(!fs::exists(root/"lola-file-transfer-downloads"/"owner"/"early"),"cancelled payload not delivered");
 check(cancel(request("never-known"))->failure=="unknown_transfer","unknown ID fails closed");
 auto reuse=request("early");check(prepare(reuse)->failure=="transfer_id_reused","cancelled ID cannot be reused");
 auto own=request("owned");check(prepare(own)->state=="Authorized","owner prepare");
 auto impostor=std::make_shared<Request>(*own);impostor->client.uuid="other";
 check(cancel(impostor)->failure=="transfer_owner_mismatch","wrong certificate owner rejected");
 check(upload(impostor)->failure=="transfer_owner_mismatch","wrong upload owner rejected");
 auto session=std::make_shared<Request>(*own);session->args["sessionId"]="other";
 check(cancel(session)->failure=="transfer_owner_mismatch","wrong session rejected");
 auto changed=std::make_shared<Request>(*own);changed->args["fileName"]="different.txt";
 check(upload(changed)->failure=="reservation_mismatch","metadata binding");
 check(cancel(own)->state=="Cancelled","wrong-owner attempts preserve real ownership");
 auto late=request("late");check(prepare(late)->state=="Authorized","late prepare");
 check(upload(late)->state=="Completed","release completed");
 check(cancel(late)->failure=="unknown_transfer","late cancellation not falsely acknowledged");
 check(fs::exists(root/"lola-file-transfer-downloads"/"owner"/"late"/"test.txt"),"late cancel preserves released file");
 auto residue=request("partial");check(prepare(residue)->state=="Authorized","partial prepare");
 auto dir=root/"lola-file-transfer-quarantine"/"owner"/"partial";fs::create_directories(dir);{std::ofstream(dir/"payload.part")<<"PART";}
 check(cancel(residue)->state=="Cancelled"&&!fs::exists(dir),"owned partial residue removed");
 auto denied=request("denied");denied->client.perm=1;check(prepare(denied)->failure=="permission_denied","upload permission required");
 auto noConsent=request("no-consent");noConsent->args["consent"]="false";check(prepare(noConsent)->failure=="consent_required","consent required");
 auto expired=request("expired");check(prepare(expired)->state=="Authorized","expiry prepare");
 lola_uploads.at("expired").expires=std::chrono::steady_clock::now()-std::chrono::seconds(1);
 check(upload(expired)->failure=="reservation_mismatch","expired reservation cannot deliver");
 check(cancel(expired)->state=="Cancelled","expired ownership remains cancellable");
 auto scan=request("scan");check(prepare(scan)->state=="Authorized","scanner prepare");scan_result=lola_scan_result::error;
 check(upload(scan)->state=="AwaitingMalwareScan","scanner outage remains quarantined");
 check(cancel(scan)->state=="Cancelled"&&!fs::exists(root/"lola-file-transfer-quarantine"/"owner"/"scan"),"scanner quarantine cancellable");
 check(!fs::exists(root/"lola-file-transfer-downloads"/"owner"/"scan"),"scanner outage no release");
 fs::remove_all(root);std::cout<<"PASS "<<cases<<" native handler contract assertions; TLS/AMSI providers stubbed\n";
}