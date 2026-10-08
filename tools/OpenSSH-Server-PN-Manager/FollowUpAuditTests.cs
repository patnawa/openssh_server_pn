using System;
using System.Collections.Generic;
using System.ServiceProcess;

namespace OpenSSHServerPNManager
{
    /// <summary>Regressions for the follow-up review of the 10.5.7.0 / Manager 2.3.1 sources.</summary>
    internal static class FollowUpAuditTests
    {
        /// <summary>A scripted service: each status read returns the next scripted value (the last one repeats).</summary>
        private sealed class FakeService
        {
            private readonly Queue<ServiceControllerStatus> _reads;
            private ServiceControllerStatus _last;
            public int Controls;
            public Func<ServiceControllerStatus, Exception> OnControl = s => null;
            public FakeService(params ServiceControllerStatus[] reads) { _reads = new Queue<ServiceControllerStatus>(reads); _last = reads[0]; }
            public ServiceControllerStatus Read() { if (_reads.Count > 0) _last = _reads.Dequeue(); return _last; }
            public void Control() { Controls++; var ex = OnControl(_last); if (ex != null) throw ex; }
        }

        private static Exception Move(FakeService svc, ServiceControllerStatus target, int timeoutMs = 2000)
        {
            try { Services.MoveTo("fixture", target, svc.Read, svc.Control, TimeSpan.FromMilliseconds(timeoutMs), ms => { }); return null; }
            catch (Exception ex) { return ex; }
        }

        internal static void Run(Action<string, Func<string>> test, string tmpDir)
        {
            test("services: a refused stop is success when the service is already stopping", () =>
            {
                // Read Running, then the SCM's recovery or another console stops it before our control arrives.
                var svc = new FakeService(ServiceControllerStatus.Running, ServiceControllerStatus.StopPending, ServiceControllerStatus.Stopped);
                svc.OnControl = s => new InvalidOperationException("Cannot stop fixture service on computer '.'.");
                var ex = Move(svc, ServiceControllerStatus.Stopped);
                if (ex != null) throw new Exception("The race failed the stop: " + ex.Message);
                return null;
            });
            test("services: a refused stop of a running service still fails", () =>
            {
                var svc = new FakeService(ServiceControllerStatus.Running);
                svc.OnControl = s => new InvalidOperationException("Cannot stop fixture service on computer '.'.");
                if (!(Move(svc, ServiceControllerStatus.Stopped) is InvalidOperationException)) throw new Exception("A genuine refusal was hidden");
                return null;
            });
            test("services: a refused start is success when the service is already starting", () =>
            {
                var svc = new FakeService(ServiceControllerStatus.Stopped, ServiceControllerStatus.StartPending, ServiceControllerStatus.Running);
                svc.OnControl = s => new InvalidOperationException("An instance of the service is already running.");
                var ex = Move(svc, ServiceControllerStatus.Running);
                if (ex != null) throw new Exception("The race failed the start: " + ex.Message);
                return null;
            });
            test("services: stopping waits for a pending start instead of sending a refused control", () =>
            {
                var svc = new FakeService(ServiceControllerStatus.StartPending, ServiceControllerStatus.StartPending, ServiceControllerStatus.Running, ServiceControllerStatus.Running, ServiceControllerStatus.StopPending, ServiceControllerStatus.Stopped);
                svc.OnControl = s => s == ServiceControllerStatus.StartPending ? new InvalidOperationException("cannot accept control") : null;
                var ex = Move(svc, ServiceControllerStatus.Stopped);
                if (ex != null) throw new Exception(ex.Message);
                if (svc.Controls != 1) throw new Exception("Expected one stop control after the start finished, got " + svc.Controls);
                return null;
            });
            test("services: a service that stops while starting fails at once, not at the timeout", () =>
            {
                var svc = new FakeService(ServiceControllerStatus.Stopped, ServiceControllerStatus.StartPending, ServiceControllerStatus.Stopped);
                var ex = Move(svc, ServiceControllerStatus.Running, 60000);
                if (!(ex is InvalidOperationException) || !ex.Message.Contains("stopped while starting")) throw new Exception("Expected an immediate start failure, got " + (ex == null ? "success" : ex.GetType().Name + ": " + ex.Message));
                return null;
            });
            test("services: a stop that never completes times out", () =>
            {
                var svc = new FakeService(ServiceControllerStatus.Running, ServiceControllerStatus.StopPending);
                var ex = Move(svc, ServiceControllerStatus.Stopped, 50);
                if (!(ex is System.ServiceProcess.TimeoutException)) throw new Exception("Expected a timeout, got " + (ex == null ? "success" : ex.GetType().Name));
                return null;
            });
        }
    }
}
