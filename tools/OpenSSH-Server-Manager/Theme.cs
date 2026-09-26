// OpenSSH Server Manager for Windows: Theme

using System;
using System.Collections.Generic;
using System.Drawing;
using System.Linq;
using System.Runtime.InteropServices;
using System.Windows.Forms;
using Microsoft.Win32;

namespace OpenSSHServerManager
{
    // ------------------------------------------------------------------------------------------
    // Colours: light (the Windows colours), dark, and high contrast (the system colours, never dark)
    // ------------------------------------------------------------------------------------------
    internal sealed class Palette
    {
        public bool Dark, HighContrast;
        /// <summary>Window and page background, text on it, grey notes (Muted) and fainter hints (Faint).</summary>
        public Color Back, Text, Muted, Faint;
        /// <summary>Lists, text boxes and other input fields.</summary>
        public Color Surface, SurfaceText;
        public Color Button, Border, Selection;
        /// <summary>State colours: running or passed (Good), stopped or failed (Bad), attention (Warn).</summary>
        public Color Good, Bad, Warn;
        /// <summary>Backgrounds of added and removed lines in a comparison.</summary>
        public Color Added, Removed;
        public Color[] Semantic { get { return new[] { Muted, Faint, Good, Bad, Warn, Text }; } }
    }

    internal static class Theme
    {
        public static Palette Current = Make(false, false);

        public static Color Back { get { return Current.Back; } }
        public static Color Text { get { return Current.Text; } }
        public static Color Muted { get { return Current.Muted; } }
        public static Color Faint { get { return Current.Faint; } }
        public static Color Good { get { return Current.Good; } }
        public static Color Bad { get { return Current.Bad; } }
        public static Color Warn { get { return Current.Warn; } }
        public static bool Dark { get { return Current.Dark; } }

        public static Palette Make(bool dark, bool highContrast)
        {
            if (highContrast)
                return new Palette
                {
                    HighContrast = true, Back = SystemColors.Control, Text = SystemColors.ControlText, Muted = SystemColors.ControlText, Faint = SystemColors.ControlText,
                    Surface = SystemColors.Window, SurfaceText = SystemColors.WindowText, Button = SystemColors.Control, Border = SystemColors.WindowFrame, Selection = SystemColors.Highlight,
                    Good = SystemColors.ControlText, Bad = SystemColors.ControlText, Warn = SystemColors.ControlText,
                    Added = SystemColors.Window, Removed = SystemColors.Window,
                };
            if (dark)
                return new Palette
                {
                    Dark = true,
                    Back = Color.FromArgb(32, 32, 32), Text = Color.FromArgb(232, 232, 232), Muted = Color.FromArgb(172, 172, 172), Faint = Color.FromArgb(145, 145, 145),
                    Surface = Color.FromArgb(43, 43, 43), SurfaceText = Color.FromArgb(232, 232, 232), Button = Color.FromArgb(58, 58, 58), Border = Color.FromArgb(96, 96, 96), Selection = Color.FromArgb(0, 95, 184),
                    Good = Color.FromArgb(108, 203, 95), Bad = Color.FromArgb(255, 110, 110), Warn = Color.FromArgb(252, 176, 72),
                    Added = Color.FromArgb(28, 64, 36), Removed = Color.FromArgb(84, 34, 34),
                };
            return new Palette
            {
                Back = SystemColors.Control, Text = SystemColors.ControlText, Muted = Color.DimGray, Faint = Color.Gray,
                Surface = SystemColors.Window, SurfaceText = SystemColors.WindowText, Button = SystemColors.Control, Border = SystemColors.ControlDark, Selection = SystemColors.Highlight,
                Good = Color.FromArgb(0, 128, 0), Bad = Color.FromArgb(192, 0, 0), Warn = Color.FromArgb(200, 110, 0),
                Added = Color.FromArgb(220, 245, 220), Removed = Color.FromArgb(250, 222, 222),
            };
        }

        /// <summary>Apps use the dark mode of Windows (Settings, Personalization, Colors): AppsUseLightTheme is 0.</summary>
        public static bool SystemUsesDark()
        {
            try
            {
                using (var k = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize"))
                    return k != null && k.GetValue("AppsUseLightTheme") is int && (int)k.GetValue("AppsUseLightTheme") == 0;
            }
            catch { return false; }
        }

        /// <summary>The palette for a preference ("system", "light", "dark"). High contrast always wins: its colours are the user's.</summary>
        public static Palette For(string pref)
        {
            if (SystemInformation.HighContrast) return Make(false, true);
            bool dark = string.Equals(pref, "dark", StringComparison.OrdinalIgnoreCase) || (!string.Equals(pref, "light", StringComparison.OrdinalIgnoreCase) && SystemUsesDark());
            return Make(dark, false);
        }

        [DllImport("dwmapi.dll")] private static extern int DwmSetWindowAttribute(IntPtr hwnd, int attr, ref int value, int size);
        [DllImport("uxtheme.dll", CharSet = CharSet.Unicode)] private static extern int SetWindowTheme(IntPtr hwnd, string app, string idList);

        /// <summary>Dark or light title bar (Windows 10 1809 and later; attribute 20 since 20H1, 19 before). Ignored elsewhere.</summary>
        public static void TitleBar(Form f)
        {
            if (!f.IsHandleCreated) return;
            try
            {
                int on = Current.Dark ? 1 : 0;
                if (DwmSetWindowAttribute(f.Handle, 20, ref on, 4) != 0) DwmSetWindowAttribute(f.Handle, 19, ref on, 4);
            }
            catch { }
        }

        /// <summary>Scroll bars and other parts drawn by the system theme: dark ones where Windows has them.</summary>
        private static void SystemParts(Control c)
        {
            if (!c.IsHandleCreated) return;
            try { SetWindowTheme(c.Handle, Current.Dark ? "DarkMode_Explorer" : "Explorer", null); } catch { }
        }

        /// <summary>
        /// Gives a window and everything in it the current colours. Colours that are not ambient (lists, text boxes, buttons)
        /// are set on each control; ambient ones (background and text of pages, panels and labels) come from the form. A
        /// label with a state or note colour of the previous palette gets the same kind of colour of the new one.
        /// </summary>
        public static void Apply(Control root, Palette previous)
        {
            var p = Current;
            var form = root as Form;
            if (form != null) TitleBar(form);
            // The light palette is what the controls show by themselves: nothing to change unless the window was dark before.
            if (!p.Dark && (previous == null || !previous.Dark)) return;
            var map = new Dictionary<int, Color>();
            if (previous != null)
            {
                var from = previous.Semantic; var to = p.Semantic;
                for (int i = 0; i < from.Length; i++) if (!map.ContainsKey(from[i].ToArgb())) map[from[i].ToArgb()] = to[i];
            }
            if (form != null) { if (p.Dark) { form.BackColor = p.Back; form.ForeColor = p.Text; } else { form.ResetBackColor(); form.ResetForeColor(); } }
            ApplyTree(root, map);
        }

        private static void ApplyTree(Control c, Dictionary<int, Color> map)
        {
            ApplyOne(c, map);
            foreach (Control child in c.Controls) ApplyTree(child, map);
        }

        private static bool IsSurface(Control c) { return c is TextBoxBase || c is ListView || c is ComboBox || c is NumericUpDown || c is ListBox || c is TreeView; }

        private static void ApplyOne(Control c, Dictionary<int, Color> map)
        {
            var p = Current; bool dark = p.Dark;
            // A colour set on purpose (a note, a state) becomes the same kind of colour of the new palette.
            Color mapped; bool semantic = !(c is Form) && !IsSurface(c) && !(c is Button) && map.TryGetValue(c.ForeColor.ToArgb(), out mapped);
            Color newFore = semantic ? map[c.ForeColor.ToArgb()] : Color.Empty;
            if (c is TabPage) { if (dark) c.BackColor = p.Back; else c.ResetBackColor(); }
            else if (IsSurface(c))
            {
                if (dark) { c.BackColor = p.Surface; c.ForeColor = p.SurfaceText; } else { c.ResetBackColor(); c.ResetForeColor(); }
                var cb = c as ComboBox; if (cb != null) cb.FlatStyle = dark ? FlatStyle.Flat : FlatStyle.Standard;
                // The sunken 3-D border is drawn white on a dark window; a single line is not.
                var border = dark ? BorderStyle.FixedSingle : BorderStyle.Fixed3D;
                if (c is TextBoxBase && ((TextBoxBase)c).BorderStyle != BorderStyle.None) ((TextBoxBase)c).BorderStyle = border;
                else if (c is ListView) ((ListView)c).BorderStyle = border;
                else if (c is UpDownBase) ((UpDownBase)c).BorderStyle = border;
                var lv = c as ListView; if (lv != null) ThemeListView(lv);
                if (c.IsHandleCreated) SystemParts(c); else c.HandleCreated += (s, e) => SystemParts((Control)s);
            }
            else if (c is Button)
            {
                var b = (Button)c;
                if (dark) { b.FlatStyle = FlatStyle.Flat; b.BackColor = p.Button; b.ForeColor = p.Text; b.FlatAppearance.BorderColor = p.Border; }
                else { b.FlatStyle = FlatStyle.Standard; b.ResetBackColor(); b.ResetForeColor(); b.UseVisualStyleBackColor = true; }
            }
            else if (c is Panel && ((Panel)c).AutoScroll) { if (c.IsHandleCreated) SystemParts(c); else c.HandleCreated += (s, e) => SystemParts((Control)s); }
            else if (c is ToolStrip)
            {
                var ts = (ToolStrip)c;
                if (dark) { ts.Renderer = new ToolStripProfessionalRenderer(new DarkColors()); ts.BackColor = p.Back; ts.ForeColor = p.Text; }
                else { ts.RenderMode = ToolStripRenderMode.ManagerRenderMode; ts.ResetBackColor(); ts.ResetForeColor(); }
            }
            if (c is LinkLabel)
            {
                var ll = (LinkLabel)c;
                ll.LinkColor = dark ? Color.FromArgb(120, 180, 255) : Color.FromArgb(0, 102, 204);
                ll.ActiveLinkColor = dark ? Color.FromArgb(160, 205, 255) : Color.Red; ll.VisitedLinkColor = dark ? Color.FromArgb(190, 150, 255) : Color.FromArgb(128, 0, 128);
            }
            if (semantic) c.ForeColor = newFore;
            var tabs = c as ThemedTabControl; if (tabs != null) tabs.UpdateTheme();
        }

        /// <summary>Dark column headers need owner drawing; rows keep the system drawing.</summary>
        private static readonly HashSet<ListView> Hooked = new HashSet<ListView>();
        /// <summary>Lists that had grid lines in the light palette (they are drawn white on dark and are switched off there).</summary>
        private static readonly HashSet<ListView> WithGrid = new HashSet<ListView>();
        [DllImport("user32.dll")] private static extern IntPtr SendMessage(IntPtr hwnd, int msg, IntPtr w, IntPtr l);

        /// <summary>The column header of a list takes the dark system style too (Windows 10 1809 and later), so the strip right of the last column is dark.</summary>
        private static void HeaderTheme(ListView lv)
        {
            if (!lv.IsHandleCreated) return;
            try { var h = SendMessage(lv.Handle, 0x101F /*LVM_GETHEADER*/, IntPtr.Zero, IntPtr.Zero); if (h != IntPtr.Zero) SetWindowTheme(h, Current.Dark ? "DarkMode_ItemsView" : "Explorer", null); } catch { }
        }

        private static void ThemeListView(ListView lv)
        {
            if (lv.View != View.Details) return;
            if (Current.Dark) { if (lv.GridLines) { WithGrid.Add(lv); lv.GridLines = false; } }
            else if (WithGrid.Remove(lv)) lv.GridLines = true;
            if (lv.IsHandleCreated) HeaderTheme(lv);
            if (!Hooked.Add(lv)) { lv.OwnerDraw = Current.Dark; lv.Invalidate(); return; }
            lv.HandleCreated += (s, e) => HeaderTheme((ListView)s);
            lv.Disposed += (s, e) => { Hooked.Remove((ListView)s); WithGrid.Remove((ListView)s); };
            lv.DrawColumnHeader += (s, e) =>
            {
                var p = Current;
                var list = (ListView)s;
                using (var bg = new SolidBrush(p.Button))
                {
                    e.Graphics.FillRectangle(bg, e.Bounds);
                    // The strip right of the last column belongs to no column: the header leaves it light otherwise.
                    if (e.ColumnIndex == list.Columns.Count - 1) e.Graphics.FillRectangle(bg, e.Bounds.Right, e.Bounds.Top, Math.Max(0, list.ClientSize.Width + 4000 - e.Bounds.Right), e.Bounds.Height);
                }
                using (var pen = new Pen(p.Border)) e.Graphics.DrawLine(pen, e.Bounds.Right - 1, e.Bounds.Top, e.Bounds.Right - 1, e.Bounds.Bottom);
                var r = new Rectangle(e.Bounds.X + 4, e.Bounds.Y, e.Bounds.Width - 6, e.Bounds.Height);
                TextRenderer.DrawText(e.Graphics, e.Header.Text, e.Font, r, p.Text, TextFormatFlags.VerticalCenter | TextFormatFlags.EndEllipsis | TextFormatFlags.NoPrefix);
            };
            lv.DrawItem += (s, e) => { e.DrawDefault = true; };
            lv.DrawSubItem += (s, e) => { e.DrawDefault = true; };
            lv.OwnerDraw = Current.Dark;
        }

        private sealed class DarkColors : ProfessionalColorTable
        {
            public override Color StatusStripGradientBegin { get { return Current.Back; } }
            public override Color StatusStripGradientEnd { get { return Current.Back; } }
            public override Color ToolStripGradientBegin { get { return Current.Back; } }
            public override Color ToolStripGradientMiddle { get { return Current.Back; } }
            public override Color ToolStripGradientEnd { get { return Current.Back; } }
            public override Color ToolStripBorder { get { return Current.Border; } }
            public override Color MenuItemSelected { get { return Current.Button; } }
            public override Color MenuItemBorder { get { return Current.Border; } }
            public override Color ToolStripDropDownBackground { get { return Current.Surface; } }
            public override Color ImageMarginGradientBegin { get { return Current.Surface; } }
            public override Color ImageMarginGradientMiddle { get { return Current.Surface; } }
            public override Color ImageMarginGradientEnd { get { return Current.Surface; } }
            public override Color MenuBorder { get { return Current.Border; } }
            public override Color SeparatorDark { get { return Current.Border; } }
            public override Color SeparatorLight { get { return Current.Border; } }
        }
    }

    /// <summary>A TabControl that draws its tab strip itself in the dark palette (the system draws it light only).</summary>
    internal sealed class ThemedTabControl : TabControl
    {
        public void UpdateTheme()
        {
            bool dark = Theme.Dark;
            if (GetStyle(ControlStyles.UserPaint) == dark) { Invalidate(); return; }
            SetStyle(ControlStyles.UserPaint | ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw, dark);
            UpdateStyles();
            RecreateHandleSafe();
        }

        private void RecreateHandleSafe() { if (IsHandleCreated) { var sel = SelectedIndex; RecreateHandle(); if (sel >= 0 && sel < TabCount) SelectedIndex = sel; } }

        protected override void OnPaint(PaintEventArgs e)
        {
            var p = Theme.Current;
            using (var bg = new SolidBrush(p.Back)) e.Graphics.FillRectangle(bg, ClientRectangle);
            for (int i = 0; i < TabCount; i++)
            {
                var r = GetTabRect(i);
                bool sel = i == SelectedIndex;
                using (var b = new SolidBrush(sel ? p.Surface : p.Button)) e.Graphics.FillRectangle(b, r);
                using (var pen = new Pen(p.Border)) e.Graphics.DrawRectangle(pen, r.X, r.Y, r.Width - 1, r.Height - 1);
                if (sel) using (var accent = new SolidBrush(p.Selection)) e.Graphics.FillRectangle(accent, r.X + 1, r.Bottom - 3, r.Width - 2, 2);
                TextRenderer.DrawText(e.Graphics, TabPages[i].Text, Font, r, sel ? p.Text : p.Muted, TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter | TextFormatFlags.NoPrefix);
            }
            if (SelectedTab != null)
            {
                var page = SelectedTab.Bounds; page.Inflate(1, 1);
                using (var pen = new Pen(p.Border)) e.Graphics.DrawRectangle(pen, page.X, page.Y, page.Width - 1, page.Height - 1);
            }
            // Focus cue for keyboard users.
            if (Focused && SelectedIndex >= 0) { var fr = GetTabRect(SelectedIndex); fr.Inflate(-3, -3); ControlPaint.DrawFocusRectangle(e.Graphics, fr, p.Text, p.Surface); }
        }
    }
}
