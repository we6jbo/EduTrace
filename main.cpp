#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QStandardPaths>
#include <QSqlDatabase>
#include <QSqlQuery>
#include <QTextStream>
#include <QDateTime>
#include <QSaveFile>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QRegularExpression>
#include <QByteArray>
#include <sodium.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <array>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <sys/types.h>
#include <sys/wait.h>
#include <vector>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <cstdio>
#include "mainwindow.h"

static QString home(){return QDir::homePath();}
static QString privateDir(){
  QByteArray overridePath=qgetenv("EDUTRACE_PRIVATE_DIR");
  if(!overridePath.isEmpty()) return QString::fromLocal8Bit(overridePath);
  QByteArray snapPath=qgetenv("SNAP_USER_DATA");
  if(!snapPath.isEmpty()) return QString::fromLocal8Bit(snapPath)+"/private";
  QByteArray xdgPath=qgetenv("XDG_DATA_HOME");
  if(!xdgPath.isEmpty()) return QString::fromLocal8Bit(xdgPath)+"/edutrace-private";
  if(QFileInfo("/var/lib/edutrace-private").isDir()) return "/var/lib/edutrace-private";
  return QDir::homePath()+"/.local/share/edutrace-private";
}
static QString vaultFile(){return privateDir()+"/secret.db";}
static QString notesFile(){return privateDir()+"/notes-oct25-26.md.enc";}
static QString sourcesFile(){return privateDir()+"/sources.json.enc";}
static bool setup(){
  QDir d; if(!d.mkpath(privateDir())) return false;
  chmod(QFile::encodeName(privateDir()).constData(),0700);
  QString dbpath=privateDir()+"/research.db";
  auto db=QSqlDatabase::addDatabase("QSQLITE");db.setDatabaseName(dbpath);
  if(!db.open()) return false;
  QSqlQuery q; bool ok=q.exec("CREATE TABLE IF NOT EXISTS research_index (id INTEGER PRIMARY KEY, category TEXT NOT NULL, created_utc TEXT NOT NULL)");
  db.close();chmod(QFile::encodeName(dbpath).constData(),0600);return ok;
}
// Local key is generated once using the OS CSPRNG, never committed to source.
// No password prompts. Anyone with access as the same OS user can use this CLI.
static bool localKey(QByteArray &key){
  const QString path=privateDir()+"/local.key";
  int fd=open(QFile::encodeName(path).constData(),O_RDONLY|O_CLOEXEC|O_NOFOLLOW);
  if(fd<0 && errno==ENOENT){
    QByteArray candidate(crypto_secretbox_KEYBYTES,0);
    randombytes_buf(candidate.data(),size_t(candidate.size()));
    fd=open(QFile::encodeName(path).constData(),O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC|O_NOFOLLOW,0600);
    if(fd>=0){
      ssize_t n=write(fd,candidate.constData(),size_t(candidate.size()));
      if(n!=candidate.size()){close(fd);unlink(QFile::encodeName(path).constData());sodium_memzero(candidate.data(),size_t(candidate.size()));return false;}
      if(fsync(fd)!=0){close(fd);unlink(QFile::encodeName(path).constData());sodium_memzero(candidate.data(),size_t(candidate.size()));return false;}
      close(fd);
    } else if(errno!=EEXIST){sodium_memzero(candidate.data(),size_t(candidate.size()));return false;}
    sodium_memzero(candidate.data(),size_t(candidate.size()));
    fd=open(QFile::encodeName(path).constData(),O_RDONLY|O_CLOEXEC|O_NOFOLLOW);
  }
  if(fd<0)return false;
  struct stat st{};
  if(fstat(fd,&st)!=0 || !S_ISREG(st.st_mode) || st.st_uid!=geteuid() || (st.st_mode&077)!=0 || st.st_size!=crypto_secretbox_KEYBYTES){close(fd);return false;}
  key.resize(crypto_secretbox_KEYBYTES);
  ssize_t n=read(fd,key.data(),size_t(key.size()));close(fd);
  if(n!=key.size()){sodium_memzero(key.data(),size_t(key.size()));key.clear();return false;}
  return true;
}
static QByteArray encryptData(const QByteArray &plain,const QByteArray &key){
  QByteArray nonce(crypto_secretbox_NONCEBYTES,0);
  randombytes_buf(nonce.data(),size_t(nonce.size()));
  QByteArray cipher(plain.size()+crypto_secretbox_MACBYTES,0);
  if(crypto_secretbox_easy(reinterpret_cast<unsigned char*>(cipher.data()),reinterpret_cast<const unsigned char*>(plain.constData()),size_t(plain.size()),reinterpret_cast<const unsigned char*>(nonce.constData()),reinterpret_cast<const unsigned char*>(key.constData()))!=0)return {};
  return "ET02"+nonce+cipher;
}
static bool decryptData(const QByteArray &input,const QByteArray &key,QByteArray &out){
  const int head=4+crypto_secretbox_NONCEBYTES;
  if(input.left(4)=="ET01")return false; // Old passphrase format: do not overwrite.
  if(input.size()<head+crypto_secretbox_MACBYTES || input.left(4)!="ET02")return false;
  QByteArray nonce=input.mid(4,crypto_secretbox_NONCEBYTES),cipher=input.mid(head);
  out.resize(cipher.size()-crypto_secretbox_MACBYTES);
  int rc=crypto_secretbox_open_easy(reinterpret_cast<unsigned char*>(out.data()),reinterpret_cast<const unsigned char*>(cipher.constData()),size_t(cipher.size()),reinterpret_cast<const unsigned char*>(nonce.constData()),reinterpret_cast<const unsigned char*>(key.constData()));
  if(rc!=0){out.fill(0);out.clear();return false;}return true;
}
static bool writePrivate(const QString &path,const QByteArray &content){
  QSaveFile f(path);if(!f.open(QIODevice::WriteOnly))return false;
  if(f.write(content)!=content.size()){f.cancelWriting();return false;}
  if(!f.commit())return false;
  chmod(QFile::encodeName(path).constData(),0600);return true;
}
static bool readPrivate(const QString &path,QByteArray &out){QFile f(path);if(!f.open(QIODevice::ReadOnly))return false;out=f.readAll();return true;}
static int store(const QString &path,bool append){
  QByteArray key;if(!localKey(key)){fprintf(stderr,"Local key unavailable or permissions unsafe.\n");return 2;}
  QByteArray plain,old;
  if(QFileInfo::exists(path)){
    if(!readPrivate(path,old)||!decryptData(old,key,plain)){
      fprintf(stderr,"Cannot decrypt existing file (ET01 requires old version and original passphrase). No changes made.\n");
      sodium_memzero(key.data(),size_t(key.size()));return 2;
    }
  }
  fprintf(stderr,"Enter private text; finish with a line containing only .END\n");fflush(stderr);
  QByteArray addition;char *line=nullptr;size_t cap=0;ssize_t n;
  while((n=getline(&line,&cap,stdin))!=-1){QByteArray part(line,int(n));if(part.trimmed()==".END")break;addition+=part;if(addition.size()>4*1024*1024){free(line);sodium_memzero(key.data(),size_t(key.size()));fprintf(stderr,"Input too large.\n");return 2;}}
  free(line);
  if(append)plain+=addition;else plain=addition;
  QByteArray cipher=encryptData(plain,key);sodium_memzero(key.data(),size_t(key.size()));sodium_memzero(plain.data(),size_t(plain.size()));
  if(cipher.isEmpty()||!writePrivate(path,cipher)){fprintf(stderr,"Save failed.\n");return 2;}
  printf("Encrypted local file updated. No network access.\n");return 0;
}
static int show(const QString &path){
  QByteArray in,out;if(!readPrivate(path,in)){fprintf(stderr,"No encrypted file exists yet.\n");return 2;}
  QByteArray key;if(!localKey(key)){fprintf(stderr,"Local key unavailable or permissions unsafe.\n");return 2;}
  bool ok=decryptData(in,key,out);sodium_memzero(key.data(),size_t(key.size()));
  if(!ok){fprintf(stderr,"Unable to decrypt file. ET01 files require the prior version.\n");return 2;}
  fwrite(out.constData(),1,size_t(out.size()),stdout);fflush(stdout);sodium_memzero(out.data(),size_t(out.size()));return 0;
}

// All searches are local and explicit; no network, shell, or model invocation.
static bool loadEncrypted(const QString &path,QByteArray &plain){
  QByteArray in,key;
  if(!readPrivate(path,in) || !localKey(key)) return false;
  bool ok=decryptData(in,key,plain);
  sodium_memzero(key.data(),size_t(key.size()));
  return ok;
}
static bool saveEncrypted(const QString &path,QByteArray &plain){
  QByteArray key;
  if(!localKey(key)) return false;
  QByteArray cipher=encryptData(plain,key);
  sodium_memzero(key.data(),size_t(key.size()));
  if(cipher.isEmpty())return false;
  return writePrivate(path,cipher);
}
static int searchNotes(const QString &query,bool question=false){
  QString term=query.trimmed();
  if(term.isEmpty()){fprintf(stderr,"Supply a search term or question.\n");return 2;}
  if(term.size()>512){fprintf(stderr,"Query too long.\n");return 2;}
  QByteArray plain;
  if(!loadEncrypted(notesFile(),plain)){
    puts("No readable encrypted notes. Existing files were not modified.");return 1;
  }
  QStringList lines=QString::fromUtf8(plain).split('\n');
  sodium_memzero(plain.data(),size_t(plain.size()));
  QStringList words;
  if(question){
    const QStringList stop={"who","what","when","where","why","how","is","are","was","were","the","a","an","about","tell","me","did","do","does","of","in","on","to","for","and","or","with","from","please"};
    for(const QString &w:term.toLower().split(QRegularExpression("[^\\p{L}\\p{N}]+"),Qt::SkipEmptyParts))
      if(w.size()>2 && !stop.contains(w)) words<<w;
  }else words<<term;
  if(words.isEmpty()){puts("Please provide a more specific question.");return 1;}
  int hits=0;
  for(int i=0;i<lines.size();++i){
    bool matched=false;
    for(const QString &w:words) if(lines[i].contains(w,Qt::CaseInsensitive)){matched=true;break;}
    if(!matched)continue;
    QString clipped=lines[i].left(500);
    printf("note line %d: %s%s\n",i+1,qPrintable(clipped),lines[i].size()>500?" [truncated]":"");
    if(++hits>=20){puts("Results limited to 20 matching lines.");break;}
  }
  if(!hits)puts("No matching passages in local notes. No answer inferred.");
  else if(question)puts("These are matching note passages, NOT an AI-generated answer or independently verified facts.");
  return hits?0:1;
}
static int addSource(){
  QByteArray old;
  QJsonArray entries;
  if(QFileInfo::exists(sourcesFile())){
    if(!loadEncrypted(sourcesFile(),old)){fprintf(stderr,"Cannot decrypt existing source catalog; no changes made.\n");return 2;}
    QJsonParseError err;
    QJsonDocument doc=QJsonDocument::fromJson(old,&err);
    sodium_memzero(old.data(),size_t(old.size()));
    if(err.error!=QJsonParseError::NoError || !doc.isArray()){fprintf(stderr,"Invalid source catalog; no changes made.\n");return 2;}
    entries=doc.array();
  }
  std::string title,reference,description;
  puts("Local source entry. Never paste sensitive data into public chats.");
  printf("Source title: ");fflush(stdout);if(!std::getline(std::cin,title))return 2;
  printf("Reference (local filename, citation, or URL as text only): ");fflush(stdout);if(!std::getline(std::cin,reference))return 2;
  printf("Description: ");fflush(stdout);if(!std::getline(std::cin,description))return 2;
  if(title.empty() || title.size()>512 || reference.size()>2048 || description.size()>4096){fprintf(stderr,"Invalid source field length.\n");return 2;}
  QJsonObject item{{"title",QString::fromStdString(title)},{"reference",QString::fromStdString(reference)},{"description",QString::fromStdString(description)},{"created_utc",QDateTime::currentDateTimeUtc().toString(Qt::ISODate)}};
  entries.append(item);
  QByteArray payload=QJsonDocument(entries).toJson(QJsonDocument::Compact);
  bool ok=saveEncrypted(sourcesFile(),payload);
  sodium_memzero(payload.data(),size_t(payload.size()));
  if(!ok){fprintf(stderr,"Source save failed.\n");return 2;}
  puts("Source metadata encrypted locally. No external requests made.");return 0;
}
static int listSources(){
  QByteArray plain;
  if(!loadEncrypted(sourcesFile(),plain)){puts("No readable encrypted source catalog.");return 1;}
  QJsonParseError err;
  QJsonDocument doc=QJsonDocument::fromJson(plain,&err);
  sodium_memzero(plain.data(),size_t(plain.size()));
  if(err.error!=QJsonParseError::NoError || !doc.isArray()){fprintf(stderr,"Invalid source catalog.\n");return 2;}
  QJsonArray arr=doc.array();
  for(int i=0;i<arr.size();++i){QJsonObject obj=arr[i].toObject();
    printf("[%d] %s | %s\n",i+1,qPrintable(obj.value("title").toString()),qPrintable(obj.value("reference").toString()));
    if(!obj.value("description").toString().isEmpty())printf("    %s\n",qPrintable(obj.value("description").toString()));
  }
  printf("%d local source entries.\n",arr.size());return 0;
}
// Optional local challenge verification. It does not authorize access to the vault.
static constexpr const char* scriptPath="/usr/local/bin/challenge.sh";
static std::string challengeKeyPath(){return (home()+"/.ads/challenge.key").toStdString();}
static constexpr const char* timePath="/tmp/fwd/challenge_time.txt";
static std::string hex(const unsigned char* p,size_t n){static constexpr char d[]="0123456789abcdef";std::string r;r.reserve(n*2);for(size_t i=0;i<n;++i){r+=d[p[i]>>4];r+=d[p[i]&15];}return r;}
static std::vector<unsigned char> unhex(const std::string &v){if(v.size()!=64)throw std::runtime_error("Invalid 256-bit key length");std::vector<unsigned char> out;for(size_t i=0;i<v.size();i+=2){auto digit=[](char c)->int{if(c>='0'&&c<='9')return c-'0';if(c>='a'&&c<='f')return c-'a'+10;return -1;};int a=digit(v[i]),b=digit(v[i+1]);if(a<0||b<0)throw std::runtime_error("Invalid key encoding");out.push_back(static_cast<unsigned char>((a<<4)|b));}return out;}
static std::string readOneLine(const char *filename){std::ifstream in(filename);if(!in)throw std::runtime_error(std::string("Cannot open ")+filename);std::string line;if(!std::getline(in,line))throw std::runtime_error("Empty file");return line;}
static std::string roundUpLocalTime(){std::time_t now=std::time(nullptr);now=((now+299)/300)*300;std::tm result{};if(!localtime_r(&now,&result))throw std::runtime_error("localtime_r failed");char s[64]{};if(!std::strftime(s,sizeof(s),"%Y-%m-%dT%H:%M:%S%z",&result))throw std::runtime_error("strftime failed");return s;}
static std::string expectedResponse(const std::string &nonce,const std::string &stamp){auto key=unhex(readOneLine(challengeKeyPath().c_str()));const std::string message="challenge-v1|"+nonce+"|"+stamp;unsigned char digest[EVP_MAX_MD_SIZE]{};unsigned int count=0;if(!HMAC(EVP_sha256(),key.data(),static_cast<int>(key.size()),reinterpret_cast<const unsigned char*>(message.data()),message.size(),digest,&count))throw std::runtime_error("HMAC failed");return hex(digest,count);}
struct ScriptResult{int exitCode;std::string output;};
static ScriptResult runScript(const std::string &nonce){int fds[2];if(pipe(fds)!=0)throw std::runtime_error("pipe failed");pid_t pid=fork();if(pid<0){close(fds[0]);close(fds[1]);throw std::runtime_error("fork failed");}if(pid==0){close(fds[0]);dup2(fds[1],STDOUT_FILENO);close(fds[1]);execl(scriptPath,scriptPath,nonce.c_str(),(char*)nullptr);_exit(127);}close(fds[1]);std::string output;char buffer[256];ssize_t n;while((n=read(fds[0],buffer,sizeof buffer))>0){if(output.size()>4096){close(fds[0]);waitpid(pid,nullptr,0);throw std::runtime_error("Challenge output too long");}output.append(buffer,n);}close(fds[0]);int status=0;if(waitpid(pid,&status,0)<0)throw std::runtime_error("waitpid failed");return {WIFEXITED(status)?WEXITSTATUS(status):-1,output};}
static std::string performChallenge(){for(int attempt=0;attempt<10;++attempt){std::array<unsigned char,16> bytes{};if(RAND_bytes(bytes.data(),bytes.size())!=1)throw std::runtime_error("RAND_bytes failed");const std::string nonce=hex(bytes.data(),bytes.size());const auto result=runScript(nonce);if(result.exitCode==3&&result.output=="DUPLICATE\n")continue;if(result.exitCode!=0)throw std::runtime_error("Script failed: "+result.output);std::istringstream in(result.output);std::string status,stamp,response,extra;if(!(in>>status>>stamp>>response)||(in>>extra)||status!="OK")throw std::runtime_error("Invalid script response");const std::string expected=expectedResponse(nonce,stamp);if(response.size()!=expected.size()||CRYPTO_memcmp(response.data(),expected.data(),expected.size())!=0)throw std::runtime_error("Challenge response authentication failed");if(readOneLine(timePath)!=stamp||roundUpLocalTime()!=stamp)throw std::runtime_error("time sync does not match");return stamp;}throw std::runtime_error("Too many duplicate random challenges");}
static int verifyChallenge(){try{std::cout<<"Verified time: "<<performChallenge()<<'\n';return 0;}catch(const std::exception &ex){std::cerr<<ex.what()<<'\n';return 1;}}

// Research session is strictly local. Activation phrases are convenience commands,
// not authentication credentials. No network calls or implicit sharing.
static int researchSession(){
  if(!isatty(STDIN_FILENO)){
    fprintf(stderr,"Research session needs an interactive terminal. Run EduTrace research.\n");return 2;
  }
  printf("EduTrace research session (local only). Commands: help, status, note, notes, search, ask, add-source, sources, challenge, exit\n");
  printf("No research text is sent to third parties. Do not paste secrets into public AI chats.\n");
  std::string line;
  while(true){
    printf("edutrace> ");fflush(stdout);
    if(!std::getline(std::cin,line)){puts("");return 0;}
    // Commands deliberately do not accept arbitrary shell arguments.
    if(line=="exit"||line=="quit"||line=="bye")return 0;
    if(line=="help"||line=="?"){
      puts("status: show private-file presence (not contents)");
      puts("note: add encrypted text; end input with .END on its own line");
      puts("notes: decrypt notes to this terminal (avoid recorded sessions)");
      puts("search TEXT: find matching lines in encrypted local notes");
      puts("ask QUESTION: show relevant note passages (not an AI answer)");
      puts("add-source: record an encrypted local source citation");
      puts("sources: list locally stored source citations");
      puts("challenge: verify local time challenge");
      puts("exit: close session");
      puts("Sharing/exporting to Moltbook, IRC, or the Internet is disabled in this release.");
    }else if(line=="status"){
      printf("EduTrace 0.7.0 | notes: %s | vault: %s | network: disabled\n",QFileInfo::exists(notesFile())?"present":"absent",QFileInfo::exists(vaultFile())?"present":"absent");
    }else if(line=="note"){
      store(notesFile(),true);
    }else if(line=="notes"){
      puts("Warning: decrypted notes will be displayed locally.");show(notesFile());puts("");
    }else if(line.rfind("search ",0)==0){
      searchNotes(QString::fromStdString(line.substr(7)));
    }else if(line.rfind("ask ",0)==0){
      searchNotes(QString::fromStdString(line.substr(4)),true);
    }else if(line=="add-source"){
      addSource();
    }else if(line=="sources"){
      listSources();
    }else if(line=="challenge"){
      verifyChallenge();
    }else if(line.empty()){
      continue;
    }else{
      puts("Unknown command. Type help. Text is not stored unless you choose note.");
    }
  }
}
int main(int argc,char**argv){
  QCoreApplication app(argc,argv);if(sodium_init()<0)return 2;
  QStringList a=app.arguments();QString cmd=a.value(1,isatty(STDIN_FILENO)?"research":"help");
  if(cmd=="help"){
    printf("EduTrace 0.7.0 | local-only research CLI\n");
    printf("Commands: research, init, status, add-note, read-notes, search TEXT, ask QUESTION, add-source, sources, set-secret, read-secret, verify-challenge, extension-path, help\n");
    printf("Private data uses EDUTRACE_PRIVATE_DIR, SNAP_USER_DATA, XDG_DATA_HOME, or legacy /var/lib; no networking or automated publication.\n");return 0;
  }
  if(cmd=="extension-path"){printf("%s/.edutrace-ext/extension.py (manual review only; never auto-executed)\n",qPrintable(home()));return 0;}
  if(cmd=="verify-challenge")return verifyChallenge();
  if(!setup()){fprintf(stderr,"Private storage setup failed.\n");return 2;}
  if(cmd=="research"||cmd=="run"||cmd=="activate")return researchSession();
  if(cmd=="init"){printf("Private storage initialized. Encrypted files are created on first write.\n");return 0;}
  if(cmd=="status"){printf("EduTrace 0.7.0 | encrypted notes: %s | encrypted vault: %s\n",QFileInfo::exists(notesFile())?"present":"absent",QFileInfo::exists(vaultFile())?"present":"absent");return 0;}
  if(cmd=="search")return searchNotes(a.mid(2).join(" "));
  if(cmd=="ask")return searchNotes(a.mid(2).join(" "),true);
  if(cmd=="add-source")return addSource();
  if(cmd=="sources")return listSources();
  if(cmd=="add-note")return store(notesFile(),true);
  if(cmd=="read-notes")return show(notesFile());
  if(cmd=="set-secret")return store(vaultFile(),false);
  if(cmd=="read-secret")return show(vaultFile());
  fprintf(stderr,"Unknown command. Run EduTrace help.\n");return 2;
}
