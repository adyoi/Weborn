/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./weborn/templates/**/*.html",
    "./weborn/static/js/**/*.js",
  ],
  theme: {
    extend: {
      colors: {
        void: "var(--bg-0)",
        pane: "var(--bg-1)",
        pane2: "var(--bg-2)",
        glass: "var(--panel)",
        line: "var(--panel-border)",
        t1: "var(--text-1)",
        t2: "var(--text-2)",
        t3: "var(--text-3)",
        accent: "var(--accent)",
        accent2: "var(--accent-2)",
        ok: "var(--ok)",
        warn: "var(--warn)",
        err: "var(--err)",
      },
      boxShadow: {
        glow: "var(--glow-cyan)",
        "glow-purple": "var(--glow-purple)",
      },
      borderRadius: {
        card: "var(--radius)",
      },
      fontFamily: {
        mono: ["Cascadia Code", "Consolas", "ui-monospace", "monospace"],
      },
    },
  },
  plugins: [],
};
