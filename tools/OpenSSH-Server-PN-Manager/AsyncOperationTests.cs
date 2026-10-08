using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace OpenSSHServerPNManager
{
    internal static class AsyncOperationTests
    {
        private const BindingFlags Private = BindingFlags.Instance | BindingFlags.NonPublic;
        private static Task<int> Start(MainForm form, Func<int> work)
        { return (Task<int>)typeof(MainForm).GetMethods(Private).Single(m => m.Name == "BgAsync" && m.IsGenericMethod).MakeGenericMethod(typeof(int)).Invoke(form, new object[] { "fixture operation", work }); }

        internal static void Run(Action<string, Func<string>> test)
        {
            test("GUI async: foreground work yields to messages and returns on the UI thread", () =>
            {
                AsyncUiTest.EnsureContext(); int uiThread = Thread.CurrentThread.ManagedThreadId;
                using (var form = new MainForm())
                using (var entered = new ManualResetEvent(false))
                using (var release = new ManualResetEvent(false))
                {
                    var handle = form.Handle; bool messageProcessed = false;
                    var work = Start(form, () => { entered.Set(); if (!release.WaitOne(5000)) throw new TimeoutException("fixture release"); return Thread.CurrentThread.ManagedThreadId; });
                    if (!entered.WaitOne(5000) || work.IsCompleted) throw new Exception("foreground call waited synchronously for its worker");
                    form.BeginInvoke((Action)(() => { messageProcessed = true; release.Set(); }));
                    AsyncUiTest.Wait(async () =>
                    {
                        int workerThread = await work;
                        if (!messageProcessed || workerThread == uiThread || Thread.CurrentThread.ManagedThreadId != uiThread)
                            throw new Exception("work or continuation ran on the wrong thread, or the UI did not process messages");
                    });
                    form.WaitForIdleForTest();
                }
                return null;
            });
            test("GUI async: a closed window cannot apply a late foreground result", () =>
            {
                AsyncUiTest.EnsureContext();
                using (var form = new MainForm())
                using (var entered = new ManualResetEvent(false))
                using (var release = new ManualResetEvent(false))
                {
                    var handle = form.Handle; bool applied = false;
                    var work = Start(form, () => { entered.Set(); if (!release.WaitOne(5000)) throw new TimeoutException("fixture release"); return 42; });
                    if (!entered.WaitOne(5000)) throw new Exception("worker did not start");
                    form.Dispose(); release.Set();
                    bool cancelled = false;
                    try { AsyncUiTest.Wait(async () => { await work; applied = true; }); }
                    catch (OperationCanceledException) { cancelled = true; }
                    if (!cancelled || applied) throw new Exception("late result was applied after disposal");
                }
                return null;
            });
            test("GUI async: the setup wizard can enter its own foreground busy scope", () =>
            {
                AsyncUiTest.EnsureContext();
                using (var form = new MainForm())
                {
                    var handle = form.Handle;
                    var wizard = typeof(MainForm).GetMethod("RunWizard", Private);
                    var safe = typeof(MainForm).GetMethod("SafeAsync", Private);
                    var running = (Task)safe.Invoke(form, new object[] { (Func<Task>)(() => (Task)wizard.Invoke(form, null)), false });
                    if (!(bool)typeof(MainForm).GetField("_wizardRunning", Private).GetValue(form))
                        throw new Exception("the foreground wrapper made the wizard reject its own request");
                    // Stop before the read-only firewall snapshot can open a modal wizard; no settings are applied.
                    form.Dispose(); AsyncUiTest.Wait(running);
                }
                return null;
            });
            test("GUI async: cancellation reaches read work while mutations expose no cancel action", () =>
            {
                AsyncUiTest.EnsureContext();
                using (var form = new MainForm())
                using (var entered = new ManualResetEvent(false))
                {
                    var handle = form.Handle;
                    var method = typeof(MainForm).GetMethod("BgCancellableAsync", Private).MakeGenericMethod(typeof(int));
                    var read = (Task<int>)method.Invoke(form, new object[] { "fixture read", (Func<CancellationToken, int>)(token =>
                        { entered.Set(); if (!token.WaitHandle.WaitOne(5000)) throw new TimeoutException("fixture cancellation"); token.ThrowIfCancellationRequested(); return 0; }) });
                    if (!entered.WaitOne(5000)) throw new Exception("cancellable reader did not start");
                    var cancel = (ToolStripButton)typeof(MainForm).GetField("_cancelButton", Private).GetValue(form);
                    cancel.PerformClick(); bool cancelled = false;
                    try { AsyncUiTest.Wait(read); } catch (OperationCanceledException) { cancelled = true; }
                    if (!cancelled || cancel.Available) throw new Exception("read cancellation did not complete or its action leaked into later work");
                    AsyncUiTest.Wait(Start(form, () => 1));
                    if (cancel.Available) throw new Exception("ordinary mutation work exposed a misleading cancellation action");
                }
                return null;
            });
            test("GUI async: a mutation dialog awaits completion and a failed callback stays editable", () =>
            {
                AsyncUiTest.EnsureContext();
                var completion = new TaskCompletionSource<int>();
                using (var dialog = new FixtureDialog(() => completion.Task))
                {
                    var handle = dialog.Handle;
                    var run = (Task)typeof(KeyTaskDialog).GetMethod("RunOkAsync", Private).Invoke(dialog, null);
                    if (run.IsCompleted || dialog.Enabled || dialog.DialogResult != DialogResult.None)
                        throw new Exception("dialog accepted or re-enabled before its mutation completed");
                    completion.SetException(new ConfigException("fixture rejected")); AsyncUiTest.Wait(run);
                    if (dialog.DialogResult == DialogResult.OK || !dialog.Enabled || dialog.LastError != "fixture rejected")
                        throw new Exception("failed asynchronous callback closed the dialog or hid its error");
                }
                completion = new TaskCompletionSource<int>();
                using (var dialog = new FixtureDialog(() => completion.Task))
                {
                    var handle = dialog.Handle;
                    var run = (Task)typeof(KeyTaskDialog).GetMethod("RunOkAsync", Private).Invoke(dialog, null);
                    completion.SetResult(0); AsyncUiTest.Wait(run);
                    if (dialog.DialogResult != DialogResult.OK) throw new Exception("successful asynchronous callback did not accept the dialog");
                }
                return null;
            });
            test("GUI async: transfer history discards superseded, cancelled, and closed-dialog reads", () =>
            {
                AsyncUiTest.EnsureContext();
                var reads = new List<TaskCompletionSource<List<TransferRecord>>>();
                var tokens = new List<CancellationToken>();
                using (var dialog = new TransfersWindow((from, to, token) =>
                {
                    var completion = new TaskCompletionSource<List<TransferRecord>>();
                    reads.Add(completion); tokens.Add(token); return completion.Task;
                }, null, new Dictionary<string, string>(), null))
                {
                    var handle = dialog.Handle;
                    var reload = typeof(TransfersWindow).GetMethod("Reload", Private);
                    var records = typeof(TransfersWindow).GetField("_records", Private);
                    var first = (Task)reload.Invoke(dialog, null);
                    var second = (Task)reload.Invoke(dialog, null);
                    if (!tokens[0].IsCancellationRequested) throw new Exception("changing the period did not cancel the preceding reader");
                    var latest = new List<TransferRecord> { new TransferRecord { Time = DateTime.Now, User = "latest", Action = TransferRecord.Upload, File = "latest.txt" } };
                    reads[1].SetResult(latest); AsyncUiTest.Wait(second);
                    reads[0].SetResult(new List<TransferRecord>());
                    bool cancelled = false;
                    try { AsyncUiTest.Wait(first); } catch (OperationCanceledException) { cancelled = true; }
                    if (!cancelled || !ReferenceEquals(records.GetValue(dialog), latest)) throw new Exception("an old period replaced the current history");
                    var third = (Task)reload.Invoke(dialog, null);
                    var cancel = (Button)typeof(TransfersWindow).GetField("_cancelRead", Private).GetValue(dialog);
                    typeof(Button).GetMethod("OnClick", Private).Invoke(cancel, new object[] { EventArgs.Empty });
                    reads[2].SetResult(new List<TransferRecord>()); cancelled = false;
                    try { AsyncUiTest.Wait(third); } catch (OperationCanceledException) { cancelled = true; }
                    if (!cancelled || !ReferenceEquals(records.GetValue(dialog), latest)) throw new Exception("cancelled history replaced the prior display");
                    var fourth = (Task)reload.Invoke(dialog, null);
                    dialog.Dispose(); reads[3].SetResult(new List<TransferRecord>()); AsyncUiTest.Wait(fourth);
                    if (!ReferenceEquals(records.GetValue(dialog), latest)) throw new Exception("a closed history dialog applied its late result");
                }
                return null;
            });
        }

        private sealed class FixtureDialog : KeyTaskDialog
        {
            private readonly Func<Task> work;
            internal FixtureDialog(Func<Task> work) : base("fixture", "Save") { this.work = work; }
            protected override Task WorkAsync() { return work(); }
        }
    }
}
