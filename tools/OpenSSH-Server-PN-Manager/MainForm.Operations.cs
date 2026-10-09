using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace OpenSSHServerPNManager
{
    internal sealed partial class MainForm
    {
        private int _busyDepth;
        private bool _timerWasRunning;
        private CancellationTokenSource _cancel;
        private readonly ToolStripButton _cancelButton = new ToolStripButton("Cancel") { Visible = false, AccessibleName = "Cancel the running operation" };
        private readonly HashSet<Task> _pendingUiOperations = new HashSet<Task>();

        private void Safe(Action action, bool show = true)
        {
            try { action(); }
            catch (Exception error) { OperationError(error, show); }
        }

        private Task SafeAsync(Func<Task> action, bool show = true) { return TrackOperation(SafeCoreAsync(action, show)); }
        private async Task SafeCoreAsync(Func<Task> action, bool show)
        {
            if (IsDisposed || Disposing) return;
            BeginBusy("Working...");
            try { await action(); }
            catch (Exception error) { OperationError(error, show); }
            finally { EndBusy(); }
        }

        // A synchronous WinForms override (keyboard dispatch) cannot return Task. This is its observed async event boundary.
        private async void RunUi(Func<Task> action, bool show = true) { await SafeAsync(action, show); }

        private void OperationError(Exception error, bool show)
        {
            if (IsDisposed || Disposing) { if (!(error is OperationCanceledException)) Log.Error("Operation after the window closed", error, false); return; }
            if (error is OperationCanceledException) { Status("Operation cancelled"); return; }
            if (error is ConfigException)
            {
                Log.Info("Configuration rejected: " + error.Message);
                if (!Program.Unattended) MessageBox.Show(this, error.Message, Program.AppName, MessageBoxButtons.OK, MessageBoxIcon.Warning);
                Status(ConfigErrorStatus(error)); return;
            }
            Log.Error("Operation failed", error, show); Status("Error: " + error.Message);
        }

        /// <summary>
        /// The status line after a refused or interrupted operation: its message's own first line, since some come after
        /// the file was saved ("Settings were saved, but ...") and must not read as "not saved".
        /// </summary>
        internal static string ConfigErrorStatus(Exception error)
        {
            var first = (error.Message ?? "").Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries).FirstOrDefault() ?? "";
            return "Stopped: " + (first.Length > 160 ? first.Substring(0, 157) + "..." : first);
        }

        private Task TrackOperation(Task task)
        {
            lock (_pendingUiOperations) _pendingUiOperations.Add(task);
            task.ContinueWith(done => { lock (_pendingUiOperations) _pendingUiOperations.Remove(done); }, CancellationToken.None, TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
            return task;
        }

        private void BeginBusy(string text)
        {
            if (IsDisposed || Disposing) throw new OperationCanceledException("The window closed.");
            if (_busyDepth++ == 0)
            {
                ++_refreshGeneration; _refreshRunning = false;
                _timerWasRunning = _timer.Enabled; _timer.Stop();
                _busy.Visible = true; UseWaitCursor = true; _tabs.Enabled = false;
                if (_navigation != null) _navigation.Enabled = false;
                if (_compactNavigation != null) _compactNavigation.Enabled = false;
                if (_trayMenu != null) _trayMenu.Enabled = false;
            }
            Status(text);
        }

        private void EndBusy()
        {
            if (_busyDepth <= 0 || --_busyDepth > 0 || IsDisposed || Disposing) return;
            _tabs.Enabled = true; UseWaitCursor = false; _busy.Visible = false; _cancelButton.Visible = false;
            if (_navigation != null) _navigation.Enabled = true;
            if (_compactNavigation != null) _compactNavigation.Enabled = true;
            if (_trayMenu != null) _trayMenu.Enabled = true;
            if (_timerWasRunning) _timer.Start();
            if (_themePending) { _themePending = false; BeginInvoke((Action)(() => Safe(ApplyTheme, false))); }
        }

        private async Task BusyAsync(string text, Func<Task> work)
        {
            BeginBusy(text);
            try { await work(); }
            finally { EndBusy(); }
        }

        private Task<T> BgAsync<T>(string text, Func<T> work) { return (Task<T>)TrackOperation(BgCoreAsync(text, work)); }

        private async Task<T> BgCoreAsync<T>(string text, Func<T> work)
        {
            if (InvokeRequired) throw new InvalidOperationException("Foreground operations must be started on the window thread.");
            BeginBusy(text);
            try
            {
                var result = await StaOperation.Run(work);
                if (IsDisposed || Disposing) throw new OperationCanceledException("The window closed before the operation completed.");
                return result;
            }
            finally { EndBusy(); }
        }

        private Task BgAsync(string text, Action work) { return BgAsync<object>(text, () => { work(); return null; }); }

        private async Task<T> BgCancellableAsync<T>(string text, Func<CancellationToken, T> work)
        {
            using (var source = new CancellationTokenSource())
            {
                _cancel = source; _cancelButton.Visible = true;
                try { return await BgAsync(text, () => work(source.Token)); }
                finally { _cancel = null; if (!IsDisposed && !Disposing) _cancelButton.Visible = false; }
            }
        }

        public void WaitForIdleForTest()
        {
            if (!Program.Unattended) throw new InvalidOperationException("This pump is available only to the unattended test harness.");
            AsyncUiTest.Wait(async () =>
            {
                while (true)
                {
                    Task[] tasks; lock (_pendingUiOperations) tasks = _pendingUiOperations.ToArray();
                    if (tasks.Length == 0) return;
                    await Task.WhenAll(tasks);
                }
            });
        }
    }

    internal static class StaOperation
    {
        internal static Task<T> Run<T>(Func<T> work)
        {
            var completion = new TaskCompletionSource<T>();
            var thread = new Thread(() =>
            {
                try { completion.SetResult(work()); }
                catch (Exception error) { completion.SetException(error); }
            }) { IsBackground = true, Name = "OpenSSH manager operation" };
            thread.SetApartmentState(ApartmentState.STA);
            thread.Start();
            return completion.Task;
        }
    }
}
