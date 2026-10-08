using System.Threading.Tasks;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Windows.Forms;

namespace OpenSSHServerPNManager
{
    internal sealed partial class MainForm
    {
        private Label _alHealth;

        private async Task RefreshAgentHealth()
        {
            ShowAgentHealth(await BgAsync("Reading background agent health...", AgentHealth.Load));
        }

        private void ShowAgentHealth(AgentHealth health)
        {
            _alHealth.Text = AgentHealthText(health, DateTime.UtcNow);
            _alHealth.ForeColor = health.FailedNotifications > 0 || health.Backlog > 0 || health.JournalGap.Length > 0 ||
                health.BlockingDegradedReason.Length > 0 || health.LastWatchError.Length > 0 || health.LastDailyError.Length > 0 ? Orange : Theme.Muted;
        }

        internal static string AgentHealthText(AgentHealth health, DateTime now)
        {
            Func<DateTime?, string> age = time => !time.HasValue ? "never" : time.Value.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss") +
                " (" + Math.Max(0, (int)(now - time.Value).TotalMinutes) + " min ago)";
            Func<Dictionary<string, int>, string> counts = values => string.Join(", ", values.OrderBy(p => p.Key).Select(p => p.Key + ": " + p.Value));
            var lines = new List<string> {
                "Last successful watch: " + age(health.LastWatchSuccessUtc) + "; daily run: " + age(health.LastDailySuccessUtc),
                "Journal checked: " + age(health.CheckpointUtc) + "; record " + health.CheckpointRecordId + "; backlog " + health.Backlog,
                "Last event: " + age(health.LastEventUtc),
                "Delivery queue: " + health.PendingNotifications + " pending (" + counts(health.PendingByDestination) + "), " +
                    health.FailedNotifications + " failed (" + counts(health.FailedByDestination) + "), " + health.ExhaustedNotifications + " awaiting explicit retry" +
                    (health.DiscardedNotifications > 0 ? ", " + health.DiscardedNotifications + " given up (kept " + (int)NotificationOutbox.ExhaustedRetention.TotalDays + " days, " + NotificationOutbox.MaxExhaustedPerDestination + " per destination)" : "")
            };
            if (health.LastWatchError.Length > 0) lines.Add("Watch failed: " + health.LastWatchError);
            if (health.LastDailyError.Length > 0) lines.Add("Daily run failed: " + health.LastDailyError);
            if (health.JournalGap.Length > 0) lines.Add("History gap at " + age(health.GapUtc) + ": " + health.JournalGap);
            if (health.LastDeliveryError.Length > 0) lines.Add("Last delivery error: " + health.LastDeliveryError);
            if (health.BlockingDegradedReason.Length > 0) lines.Add("Automatic blocking deferred: " + health.BlockingDegradedReason);
            return string.Join(Environment.NewLine, lines);
        }

        private async Task RetryNotifications()
        {
            var settings = AlertSettings.Load();
            int count = await BgAsync("Requeuing failed deliveries...", () => NotificationOutbox.RetryFailed(settings));
            await RefreshAgentHealth();
            Status(count + " failed delivery destination(s) queued with the saved transport settings; original recipients preserved");
        }
    }
}
