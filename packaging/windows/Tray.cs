using System;
using System.Diagnostics;
using System.Drawing;
using System.Globalization;
using System.IO;
using System.ServiceProcess;
using System.Threading;
using System.Web.Script.Serialization;
using System.Windows.Forms;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Security.Principal;

internal sealed class Tray : ApplicationContext {
  readonly NotifyIcon icon;
  readonly ContextMenuStrip menu;
  readonly string prefs=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),"AidotVPN","tray.json");
  bool korean=CultureInfo.CurrentUICulture.Name.StartsWith("ko");
  bool controlling;
  bool exiting;
  readonly System.Windows.Forms.Timer timer = new System.Windows.Forms.Timer();
  string Text(string ko,string en){return korean?ko:en;}
  static string InstallDir {get{return AppDomain.CurrentDomain.BaseDirectory;}}
  static string BuildVersion {get{return FileVersionInfo.GetVersionInfo(typeof(Tray).Assembly.Location).ProductVersion;}}
  [STAThread] static int Main(string[] args) {
    if(args.Length==1 && (args[0]=="--stop-server" || args[0]=="--start-server")) {
      return ApplyControl(args[0]=="--stop-server");
    }
    Application.EnableVisualStyles();Application.SetCompatibleTextRenderingDefault(false);
    bool created;
    using(var mutex=new Mutex(true,"Local\\AidotVPN.Tray",out created)) {
      if(!created){OpenBrowser(args.Length>0 && args[0]=="--settings");return 0;}
      using(var tray=new Tray()) { if(args.Length>0 && args[0]=="--settings")OpenBrowser(true); Application.Run(tray); }
    }
    return 0;
  }
  Tray() {
    try {var data=new JavaScriptSerializer().Deserialize<Dictionary<string,string>>(File.ReadAllText(prefs));korean=data["language"]=="ko";}catch{}
    menu=new ContextMenuStrip();
    icon=new NotifyIcon { Icon=Icon.ExtractAssociatedIcon(Application.ExecutablePath),Visible=true,ContextMenuStrip=menu,Text="AidotVPN Server" };
    icon.MouseClick+=(s,e)=>{if(e.Button==MouseButtons.Left)Open(false);};
    Rebuild();timer.Interval=5000;timer.Tick+=(s,e)=>UpdateStatus();timer.Start();UpdateStatus();
  }
  void Rebuild() {
    menu.Items.Clear();
    menu.Items.Add("aidot-vpn "+BuildVersion,null,(s,e)=>ShowInformation());
    menu.Items.Add(Text("콘솔 열기","Open console"),null,(s,e)=>Open(false));
    menu.Items.Add(Text("설정","Settings"),null,(s,e)=>Open(true));
    menu.Items.Add(Text("서버 시작","Start server"),null,async(s,e)=>await ControlServer(false));
    var language=new ToolStripMenuItem("Language / 언어");
    language.DropDownItems.Add("English",null,(s,e)=>Language(false));language.DropDownItems.Add("한국어",null,(s,e)=>Language(true));menu.Items.Add(language);
    menu.Items.Add(new ToolStripSeparator());
    menu.Items.Add(Text("아이콘만 닫기 (서버 유지)","Close tray (keep server running)"),null,(s,e)=>ExitThread());
    menu.Items.Add(Text("종료 (서버 중지)","Exit (stop server)"),null,async(s,e)=>await ExitServer());
  }
  async Task ExitServer() {
    if(controlling || exiting)return;
    exiting=true;
    try {
      var idle=await Task.Run(()=>AidotServiceControl.NothingToStop(n=>new WindowsAidotService(n)));
      if(!idle && MessageBox.Show(Text("등록된 aidot-vpn 제어 서버와 콘솔 서비스를 중지하고 종료할까요?","Stop the registered aidot-vpn controller and console services, then exit?"),"aidot-vpn",MessageBoxButtons.OKCancel,MessageBoxIcon.Question)!=DialogResult.OK)return;
      if(await ControlServer(true))ExitThread();
    }finally{exiting=false;}
  }
  void ShowInformation() {
    var lines=new List<string>{"aidot-vpn "+BuildVersion,Text("Windows 서비스용 트레이","Windows service tray"),Application.ExecutablePath,""};
    foreach(var name in AidotServiceControl.Names){
      try {using(var service=new WindowsAidotService(name)){lines.Add(name+": "+service.Read());}}
      catch(Exception e){var code=AidotServiceControl.NativeError(e);lines.Add(name+": "+(code==1060?Text("미설치","Not installed"):Text("조회 실패, Windows 오류 ","Query failed, Windows error ")+code));}
    }
    lines.Add("");lines.Add(Text("소스 ZIP을 바꿔도 설치된 프로그램은 갱신되지 않습니다. Windows 서비스 설치 파일로 업데이트하세요.","Replacing the source ZIP does not update the installed program. Update with the Windows service installer."));
    MessageBox.Show(String.Join(Environment.NewLine,lines),"aidot-vpn",MessageBoxButtons.OK,MessageBoxIcon.Information);
  }
  void Language(bool value) {korean=value;Directory.CreateDirectory(Path.GetDirectoryName(prefs));File.WriteAllText(prefs,new JavaScriptSerializer().Serialize(new {language=korean?"ko":"en"}));Rebuild();UpdateStatus();}
  void Open(bool settings) {
    try {OpenBrowser(settings);}catch(Exception e){MessageBox.Show(Text("콘솔을 열지 못했습니다. 서버 상태와 접속 주소를 확인하세요.","Could not open the console. Check server status and the console address.")+"\n"+e.GetType().Name,"AidotVPN");}
  }
  static void OpenBrowser(bool settings) {
    var file=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),"AidotVPN","public","console-endpoint.json");
    var url="http://127.0.0.1:9111";
    if(File.Exists(file)) {var data=new JavaScriptSerializer().Deserialize<Dictionary<string,string>>(File.ReadAllText(file));url=data["url"];}
    Uri address;
    if(!Uri.TryCreate(url,UriKind.Absolute,out address) || (address.Scheme!="http" && address.Scheme!="https") || !String.IsNullOrEmpty(address.UserInfo) || address.AbsolutePath!="/" || address.Query!="" || address.Fragment!="")throw new InvalidDataException("Invalid console URL");
    Process.Start(new ProcessStartInfo(address.GetLeftPart(UriPartial.Authority)+(settings?"/?settings=1":"/")){UseShellExecute=true});
  }
  static int ApplyControl(bool stop) {
    return AidotServiceControl.Apply(stop,n=>new WindowsAidotService(n),()=>File.Exists(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),"AidotVPN","controller","controller.env")));
  }
  static int RequestControl(bool stop) {
    return AidotServiceControl.Request(stop,n=>new WindowsAidotService(n),()=>File.Exists(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),"AidotVPN","controller","controller.env")),()=>new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator),()=>{
      using(var p=Process.Start(new ProcessStartInfo(Path.Combine(InstallDir,"aidotvpn-tray.exe"),stop?"--stop-server":"--start-server"){UseShellExecute=true,Verb="runas"})){
        if(p==null)return 1;p.WaitForExit();return p.ExitCode;
      }
    });
  }
  async Task<bool> ControlServer(bool stop) {
    if(controlling)return false;
    controlling=true;menu.Enabled=false;icon.Text="AidotVPN · "+(stop?Text("서버 중지 중","Stopping server"):Text("서버 시작 중","Starting server"));
    int result;
    try {result=await Task.Run(()=>RequestControl(stop));}
    finally {controlling=false;menu.Enabled=true;UpdateStatus();}
    LogControl(stop,result);
    if(result==0)return true;
    var code=result&65535;
    string message;
    switch(code){
      case 1223:message=stop?Text("Windows 관리자 승인이 취소되었습니다. 서버를 중지하려면 종료를 다시 선택하고 승인하세요.","Windows administrator approval was canceled. To stop the server, choose Exit again and approve the request."):Text("Windows 관리자 승인이 취소되었습니다. 서버 시작을 다시 선택하고 승인하세요.","Windows administrator approval was canceled. Choose Start server again and approve the request.");break;
      case 5:case 740:case 1314:message=Text("이 계정에는 서비스 제어 권한이 없습니다. Windows 관리자 계정으로 승인하세요.","This account does not have permission to control the service. Approve using a Windows administrator account.");break;
      case 1060:message=Text("AidotVPN 서비스가 등록되지 않았습니다. 최신 설치 파일을 다시 실행해 설치를 복구하세요.","The AidotVPN service is not installed. Run the latest installer again to repair the installation.");break;
      case 1460:case 1053:message=Text("서비스 응답 시간이 초과되었습니다. 서비스 상태와 로그를 확인한 후 다시 시도하세요.","The service did not respond in time. Check its status and logs, then try again.");break;
      case 1058:message=Text("Windows에서 서비스가 사용 안 함으로 설정되어 있습니다. 서비스 시작 유형을 확인하세요.","The service is disabled in Windows. Check its startup type.");break;
      case 1069:message=Text("서비스 계정으로 로그인하지 못했습니다. 서비스 계정 설정을 확인하세요.","Windows could not sign in with the service account. Check the service account settings.");break;
      case 2:case 3:message=Text("서버 제어 실행 파일을 찾지 못했습니다. 설치를 복구하세요.","The server control executable could not be found. Repair the installation.");break;
      default:message=stop?Text("서버를 중지하지 못했습니다. 서비스 상태와 로그를 확인하세요.","Could not stop the server. Check the service status and logs."):Text("서버를 시작하지 못했습니다. 서비스 설정과 로그를 확인하세요.","Could not start the server. Check the service configuration and logs.");break;
    }
    MessageBox.Show(message+"\n\n"+AidotServiceControl.ServiceName(result)+" · "+Text("Windows 오류 ","Windows error ")+code,"AidotVPN",MessageBoxButtons.OK,MessageBoxIcon.Warning);
    return false;
  }
  void LogControl(bool stop,int result) {
    try {var dir=Path.Combine(Path.GetDirectoryName(prefs),"logs");Directory.CreateDirectory(dir);var file=Path.Combine(dir,"tray.log");if(File.Exists(file) && new FileInfo(file).Length>1024*1024){if(File.Exists(file+".1"))File.Delete(file+".1");File.Move(file,file+".1");}File.AppendAllText(file,DateTime.UtcNow.ToString("o")+" version="+BuildVersion+" executable="+Application.ExecutablePath+" action="+(stop?"stop":"start")+" result="+result+" service="+AidotServiceControl.ServiceName(result)+Environment.NewLine);}
    catch { }
  }
  void UpdateStatus() {if(controlling)return;try {using(var s=new ServiceController("AidotVpnConsole"))icon.Text="AidotVPN · "+(s.Status==ServiceControllerStatus.Running?Text("콘솔 실행 중","Console running"):Text("콘솔 중지됨","Console stopped"));}catch{icon.Text="AidotVPN · "+Text("서비스 미설치","Service not installed");}}
  protected override void ExitThreadCore(){timer.Stop();icon.Visible=false;icon.Dispose();menu.Dispose();base.ExitThreadCore();}
}
