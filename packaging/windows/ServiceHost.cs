// Compiled setup infrastructure; never executes scripts or commands from user AppData.
using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.ServiceProcess;
using System.Text;
using System.Threading;

internal sealed class ServiceHost : ServiceBase {
  readonly string component;
  Process child;
  IntPtr job;
  volatile bool stopping;
  readonly object logLock = new object();
  string logFile;
  ServiceHost(string name) { component=name; ServiceName=name=="console"?"AidotVpnConsole":"AidotVpnController"; CanStop=true; CanShutdown=true; AutoLog=true; }
  static int Main(string[] args) {
    if(args.Length!=1 || (args[0]!="console" && args[0]!="controller")) return 2;
    ServiceBase.Run(new ServiceHost(args[0])); return 0;
  }
  protected override void OnStart(string[] args) {
    stopping=false;
    var root=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),"AidotVPN");
    var data=Path.Combine(root,component);
    Directory.CreateDirectory(Path.Combine(data,"logs"));
    logFile=Path.Combine(data,"logs","service.log");
    var exe=Path.Combine(AppDomain.CurrentDomain.BaseDirectory,"aidotvpn-"+component+".exe");
    var start=new ProcessStartInfo(exe) { UseShellExecute=false, CreateNoWindow=true, WorkingDirectory=data, RedirectStandardInput=true, RedirectStandardOutput=true, RedirectStandardError=true, StandardOutputEncoding=Encoding.UTF8, StandardErrorEncoding=Encoding.UTF8 };
    start.EnvironmentVariables.Remove("NODE_OPTIONS");
    start.EnvironmentVariables["AIDOTVPN_SCOPE"]="system";
    start.EnvironmentVariables["AIDOTVPN_DATA_DIR"]=data;
    start.EnvironmentVariables["AIDOTVPN_CONFIG_DIR"]=Path.Combine(data,"config");
    start.EnvironmentVariables["AIDOTVPN_SERVICE_STDIN"]="1";
    start.EnvironmentVariables["AIDOTVPN_ENV_FILE"]=component=="controller"?Path.Combine(data,"controller.env"):"";
    if(component=="console") start.EnvironmentVariables["AIDOTVPN_ENDPOINT_FILE"]=Path.Combine(root,"public","console-endpoint.json");
    job=CreateJobObject(IntPtr.Zero,null);
    if(job==IntPtr.Zero) throw new System.ComponentModel.Win32Exception();
    var limits=new JobLimits(); limits.Basic.LimitFlags=0x2000; // KILL_ON_JOB_CLOSE
    if(!SetInformationJobObject(job,9,ref limits,(uint)Marshal.SizeOf(limits))) throw new System.ComponentModel.Win32Exception();
    child=new Process { StartInfo=start, EnableRaisingEvents=true };
    child.OutputDataReceived+=(s,e)=>Log(e.Data);child.ErrorDataReceived+=(s,e)=>Log(e.Data);
    child.Exited+=(s,e)=>{ if(!stopping) {Log("Child exited unexpectedly; requesting SCM recovery.");Environment.Exit(1);} };
    if(!child.Start()) throw new InvalidOperationException("Could not start server");
    if(!AssignProcessToJobObject(job,child.Handle)) {child.Kill();throw new System.ComponentModel.Win32Exception();}
    child.BeginOutputReadLine();child.BeginErrorReadLine();
    Log("Service started, child PID "+child.Id);
  }
  void Log(string message) {
    if(message==null || logFile==null)return;
    lock(logLock) try {
      if(File.Exists(logFile) && new FileInfo(logFile).Length>10*1024*1024){if(File.Exists(logFile+".1"))File.Delete(logFile+".1");File.Move(logFile,logFile+".1");}
      File.AppendAllText(logFile,DateTime.UtcNow.ToString("o")+" "+message+Environment.NewLine,Encoding.UTF8);
    } catch { }
  }
  protected override void OnStop() {
    stopping=true;
    RequestAdditionalTime(25000);
    if(child!=null) {
      try {if(!child.HasExited){child.StandardInput.WriteLine("shutdown");child.StandardInput.Flush();if(!child.WaitForExit(20000))child.Kill();}}catch(Exception e){Log("Shutdown: "+e.GetType().Name);}
      child.Dispose();child=null;
    }
    if(job!=IntPtr.Zero){CloseHandle(job);job=IntPtr.Zero;}
    Log("Service stopped");
  }
  protected override void OnShutdown() {OnStop();base.OnShutdown();}
  [StructLayout(LayoutKind.Sequential)] struct BasicLimits { public long PerProcessUserTimeLimit,PerJobUserTimeLimit; public uint LimitFlags; public UIntPtr MinimumWorkingSetSize,MaximumWorkingSetSize;public uint ActiveProcessLimit;public UIntPtr Affinity;public uint PriorityClass,SchedulingClass; }
  [StructLayout(LayoutKind.Sequential)] struct IoCounters {public ulong ReadOperationCount,WriteOperationCount,OtherOperationCount,ReadTransferCount,WriteTransferCount,OtherTransferCount;}
  [StructLayout(LayoutKind.Sequential)] struct JobLimits {public BasicLimits Basic;public IoCounters Io;public UIntPtr ProcessMemoryLimit,JobMemoryLimit,PeakProcessMemoryUsed,PeakJobMemoryUsed;}
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr CreateJobObject(IntPtr attributes,string name);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool SetInformationJobObject(IntPtr job,int infoClass,ref JobLimits limits,uint length);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool AssignProcessToJobObject(IntPtr job,IntPtr process);
  [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
}
