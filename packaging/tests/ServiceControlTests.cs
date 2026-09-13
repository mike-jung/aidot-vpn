using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.ServiceProcess;

internal sealed class FakeAidotService : IAidotService {
  internal ServiceControllerStatus state;
  internal int stops,starts,waits;
  internal Exception readError,stopError,waitError;
  internal bool stoppedBeforeError;
  internal FakeAidotService(ServiceControllerStatus value){state=value;}
  public ServiceControllerStatus Read(){if(readError!=null)throw readError;return state;}
  public void Start(){starts++;state=ServiceControllerStatus.Running;}
  public void Stop(){stops++;if(stoppedBeforeError)state=ServiceControllerStatus.Stopped;if(stopError!=null)throw stopError;state=ServiceControllerStatus.Stopped;}
  public void Wait(ServiceControllerStatus value){waits++;if(waitError!=null)throw waitError;state=value;}
  public void Dispose(){}
}
internal static class ServiceControlTests {
  static readonly List<string> checks=new List<string>();
  static void Check(bool ok,string name){if(!ok)throw new Exception(name);checks.Add(name);}
  static int Main(){try {
    Func<string,IAidotService> absent=n=>{throw new InvalidOperationException("missing",new Win32Exception(1060));};
    Check(AidotServiceControl.NothingToStop(absent),"missing services do not require elevation to exit");
    Check(AidotServiceControl.Apply(true,absent,()=>false)==0,"missing services are a successful stop");
    var a=new FakeAidotService(ServiceControllerStatus.Stopped);
    Check(AidotServiceControl.Apply(true,n=>a,()=>false)==0 && a.stops==0,"already stopped services are idempotent");
    a=new FakeAidotService(ServiceControllerStatus.StopPending);
    Check(AidotServiceControl.Apply(true,n=>a,()=>false)==0 && a.stops==0 && a.waits==1,"stop pending waits without sending a second stop");
    a=new FakeAidotService(ServiceControllerStatus.StartPending);
    Check(AidotServiceControl.Apply(true,n=>a,()=>false)==0 && a.stops==1 && a.waits==2,"exit during startup waits then stops");
    a=new FakeAidotService(ServiceControllerStatus.Running){stopError=new Win32Exception(5)};
    var b=new FakeAidotService(ServiceControllerStatus.Running);
    var result=AidotServiceControl.Apply(true,n=>n=="AidotVpnConsole"?a:b,()=>false);
    Check((result&65535)==5 && AidotServiceControl.ServiceName(result)=="AidotVpnConsole" && b.stops==1,"permission error identifies the service and still stops the other service");
    a=new FakeAidotService(ServiceControllerStatus.StopPending){waitError=new System.ServiceProcess.TimeoutException()};
    result=AidotServiceControl.Apply(true,n=>a,()=>false);
    Check((result&65535)==1460,"timeout remains distinct from administrator denial");
    result=AidotServiceControl.Apply(false,absent,()=>false);
    Check((result&65535)==1060 && AidotServiceControl.ServiceName(result)=="AidotVpnConsole","starting an uninstalled console reports missing service");
    a=new FakeAidotService(ServiceControllerStatus.Stopped);
    result=AidotServiceControl.Apply(false,n=>{if(n=="AidotVpnController")throw new Exception("unconfigured controller queried");return a;},()=>false);
    Check(result==0 && a.starts==1,"console can start before controller provisioning");
    a=new FakeAidotService(ServiceControllerStatus.Running){stopError=new Win32Exception(1062),stoppedBeforeError=true};
    Check(AidotServiceControl.Apply(true,n=>a,()=>false)==0,"concurrent stop completion is successful");
    Check(AidotServiceControl.NativeError(new Win32Exception(1223))==1223,"Windows UAC cancellation retains its own error code");
    Console.WriteLine("{\"passed\":"+checks.Count+",\"checks\":[\""+String.Join("\",\"",checks)+"\"]}");return 0;
  }catch(Exception e){Console.Error.WriteLine(e);return 1;}}
}
