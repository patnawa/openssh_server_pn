using System;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace OpenSSHServerPNManager
{
    /// <summary>The synchronous unattended harness owns a message pump; production operations always await.</summary>
    internal static class AsyncUiTest
    {
        internal static void Wait(Func<Task> work) { EnsureContext(); Wait(work()); }
        internal static T Wait<T>(Func<Task<T>> work) { EnsureContext(); return Wait(work()); }
        internal static void EnsureContext()
        {
            if (!Program.Unattended) throw new InvalidOperationException("Only the unattended harness may install its UI context.");
            if (!(SynchronizationContext.Current is WindowsFormsSynchronizationContext))
                SynchronizationContext.SetSynchronizationContext(new WindowsFormsSynchronizationContext());
        }
        internal static void Wait(Task task)
        {
            if (!Program.Unattended) throw new InvalidOperationException("Only the unattended harness may pump an asynchronous test.");
            var timer = Stopwatch.StartNew();
            while (!task.IsCompleted)
            {
                if (timer.Elapsed > TimeSpan.FromSeconds(60)) throw new TimeoutException("An asynchronous UI operation did not finish within 60 seconds.");
                Application.DoEvents(); Thread.Sleep(1);
            }
            task.GetAwaiter().GetResult();
        }
        internal static T Wait<T>(Task<T> task) { Wait((Task)task); return task.GetAwaiter().GetResult(); }
    }
}
