using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.ServiceProcess;

// Only the two product services can be controlled. Windows still enforces their ACLs.
internal interface IAidotService : IDisposable {
  ServiceControllerStatus Read();
  void Start();
  void Stop();
  void Wait(ServiceControllerStatus state);
}
internal sealed class WindowsAidotService : IAidotService {
  readonly ServiceController service;
  readonly string name;
  internal WindowsAidotService(string value) {
    if(value!="AidotVpnConsole" && value!="AidotVpnController")throw new ArgumentException("Unknown product service");
    name=value;service=new ServiceController(value);
  }
  public ServiceControllerStatus Read(){service.Refresh();return service.Status;}
  public void Start(){service.Start();}
  public void Wait(ServiceControllerStatus state){service.WaitForStatus(state,TimeSpan.FromSeconds(35));}
  public void Stop(){
    // Do not stop unrelated services that an administrator may have made dependent on us.
    var manager=OpenSCManager(null,null,1);
    if(manager==IntPtr.Zero)throw new Win32Exception(Marshal.GetLastWin32Error());
    try {
      var handle=OpenService(manager,name,0x20);
      if(handle==IntPtr.Zero)throw new Win32Exception(Marshal.GetLastWin32Error());
      try {ServiceStatus status;if(!ControlService(handle,1,out status))throw new Win32Exception(Marshal.GetLastWin32Error());}
      finally {CloseServiceHandle(handle);}
    } finally {CloseServiceHandle(manager);}
  }
  public void Dispose(){service.Dispose();}
  [StructLayout(LayoutKind.Sequential)] struct ServiceStatus {public uint type,state,accepted,win32Exit,specificExit,checkpoint,waitHint;}
  [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr OpenSCManager(string machine,string database,uint access);
  [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr OpenService(IntPtr manager,string name,uint access);
  [DllImport("advapi32.dll",SetLastError=true)] static extern bool ControlService(IntPtr service,uint control,out ServiceStatus status);
  [DllImport("advapi32.dll")] static extern bool CloseServiceHandle(IntPtr handle);
}
internal static class AidotServiceControl {
  internal static readonly string[] Names={"AidotVpnConsole","AidotVpnController"};
  internal static int NativeError(Exception error) {
    for(var current=error;current!=null;current=current.InnerException){
      var native=current as Win32Exception;if(native!=null)return native.NativeErrorCode;
      if(current is System.ServiceProcess.TimeoutException || current is System.TimeoutException)return 1460;
      if(current is UnauthorizedAccessException)return 5;
    }
    return 1;
  }
  internal static int Encode(string service,int code){return ((service==Names[0]?1:2)<<16)|(code>0 && code<65536?code:1);}
  internal static string ServiceName(int result){var index=result>>16;return index==1?Names[0]:index==2?Names[1]:"AidotVPN";}
  internal static int Request(bool stop,Func<string,IAidotService> open,Func<bool> controllerConfigured,Func<bool> administrator,Func<int> elevate) {
    // Try with the caller's existing rights first. Missing/stopped services are
    // successful stops, and missing services on start are not permission errors.
    try {
      var result=Apply(stop,open,controllerConfigured);
      var code=result&65535;
      if((code==5 || code==740 || code==1314) && !administrator())return elevate();
      return result;
    }catch(Exception e){return NativeError(e);}
  }
  internal static bool NothingToStop(Func<string,IAidotService> open) {
    foreach(var name in Names){
      try {using(var service=open(name)){if(service.Read()!=ServiceControllerStatus.Stopped)return false;}}
      catch(Exception e){if(NativeError(e)!=1060)return false;}
    }
    return true;
  }
  internal static int Apply(bool stop,Func<string,IAidotService> open,Func<bool> controllerConfigured) {
    int failure=0;
    foreach(var name in stop?Names:new[]{Names[1],Names[0]}){
      try {
        if(!stop && name==Names[1] && !controllerConfigured())continue;
        using(var service=open(name)){
          var state=service.Read();
          if(state==ServiceControllerStatus.StopPending){service.Wait(ServiceControllerStatus.Stopped);state=service.Read();}
          if(state==ServiceControllerStatus.StartPending || state==ServiceControllerStatus.ContinuePending){service.Wait(ServiceControllerStatus.Running);state=service.Read();}
          if(state==ServiceControllerStatus.PausePending){service.Wait(ServiceControllerStatus.Paused);state=service.Read();}
          if(stop){
            if(state==ServiceControllerStatus.Stopped)continue;
            try {service.Stop();}catch(Exception e){if(NativeError(e)!=1062 || service.Read()!=ServiceControllerStatus.Stopped)throw;}
            service.Wait(ServiceControllerStatus.Stopped);
          }else{
            if(state==ServiceControllerStatus.Running)continue;
            if(state!=ServiceControllerStatus.Stopped)throw new Win32Exception(1061);
            try {service.Start();}catch(Exception e){if(NativeError(e)!=1056)throw;}
            service.Wait(ServiceControllerStatus.Running);
          }
        }
      }catch(Exception e){
        var code=NativeError(e);
        if(stop && code==1060)continue; // Absent services cannot keep a tray icon alive.
        if(failure==0)failure=Encode(name,code);
        // Continue to the other product service even when this one fails.
      }
    }
    return failure;
  }
}
