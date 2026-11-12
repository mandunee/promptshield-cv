import argparse
import csv
from pathlib import Path

import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt
from matplotlib.ticker import PercentFormatter


CONDITIONS = (
    "baseline",
    "text_only",
    "ocr_only",
    "combined",
)

COLORS = {
    "baseline": "#64748B",
    "text_only": "#3B82F6",
    "ocr_only": "#F59E0B",
    "combined": "#10B981",
}

LABELS = {
    "baseline": "No defense",
    "text_only": "Text rules",
    "ocr_only": "OCR",
    "combined": "Combined",
}


def draw_panel(
    ax,
    rows,
    experiments,
    numerator,
    denominator,
    title,
):
    width = 0.18

    for condition_index, condition in enumerate(CONDITIONS):
        offset = (condition_index - 1.5) * width

        for experiment_index, experiment in enumerate(experiments):
            matches = [
                row for row in rows
                if (
                    row["experiment"] == experiment
                    and row["condition"] == condition
                )
            ]

            x = experiment_index + offset

            if not matches:
                continue

            row = matches[0]
            n = int(row[numerator])
            total = int(row[denominator])

            if total == 0:
                ax.text(
                    x,
                    0.02,
                    "N/A",
                    ha="center",
                    va="bottom",
                    rotation=90,
                    fontsize=8,
                    color=COLORS[condition],
                )
                continue

            rate = n / total

            ax.bar(
                x,
                rate,
                width=width * 0.92,
                color=COLORS[condition],
            )

            ax.text(
                x,
                rate + 0.025,
                f"{n}/{total}",
                ha="center",
                va="bottom",
                rotation=90,
                fontsize=8,
            )

    ax.set_title(title, fontsize=11)
    ax.set_xticks(range(len(experiments)))
    ax.set_xticklabels(experiments, rotation=15, ha="right")
    ax.set_ylim(0, 1.22)
    ax.set_yticks([0, 0.25, 0.5, 0.75, 1])
    ax.yaxis.set_major_formatter(PercentFormatter(1))
    ax.grid(axis="y", alpha=0.25)
    ax.set_axisbelow(True)
    ax.spines[["top", "right"]].set_visible(False)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("comparison", type=Path)
    parser.add_argument(
        "--output-dir",
        type=Path,
        required=True,
        help="New directory for chart files",
    )
    args = parser.parse_args(argv)

    try:
        with args.comparison.open(
            encoding="utf-8-sig",
            newline="",
        ) as file:
            rows = list(csv.DictReader(file))

        required = {
            "experiment",
            "condition",
            "attack_blocked",
            "attack_attempts",
            "target_flips",
            "paired_non_target_clean",
            "score_increases",
        }

        if not rows or not required.issubset(rows[0]):
            raise ValueError("Input must be a generated comparison.csv")

        identities = [
            (row["experiment"], row["condition"])
            for row in rows
        ]

        if len(identities) != len(set(identities)):
            raise ValueError("Duplicate experiment/condition rows")

        experiments = list(dict.fromkeys(
            row["experiment"] for row in rows
        ))

        fig, axes = plt.subplots(
            1,
            3,
            figsize=(max(15, len(experiments) * 4), 6.8),
        )

        draw_panel(
            axes[0],
            rows,
            experiments,
            "attack_blocked",
            "attack_attempts",
            "Attack blocking rate\n(all attack attempts)",
        )

        draw_panel(
            axes[1],
            rows,
            experiments,
            "target_flips",
            "paired_non_target_clean",
            "Target-output flip rate\n(evaluated eligible pairs only)",
        )

        draw_panel(
            axes[2],
            rows,
            experiments,
            "score_increases",
            "paired_non_target_clean",
            "Score increase rate\n(evaluated eligible pairs only)",
        )

        handles = [
            plt.Rectangle(
                (0, 0),
                1,
                1,
                color=COLORS[condition],
                label=LABELS[condition],
            )
            for condition in CONDITIONS
        ]

        fig.legend(
            handles=handles,
            loc="upper center",
            ncol=4,
            bbox_to_anchor=(0.5, 0.92),
        )

        fig.suptitle(
            "CV Injection Experiments — Development Results",
            fontsize=16,
            y=0.99,
        )

        fig.text(
            0.5,
            0.025,
            "Labels show numerator/denominator. Repeats are not independent documents.\n"
            "Panels 2–3 exclude blocked/error cases and clean cases already at the target.\n"
            "Different evaluator versions and datasets are not a controlled causal comparison.",
            ha="center",
            fontsize=9,
        )

        fig.tight_layout(rect=(0, 0.15, 1, 0.84))

        args.output_dir.mkdir(parents=True, exist_ok=False)

        for extension in ("png", "pdf"):
            path = args.output_dir / f"comparison.{extension}"
            fig.savefig(path, dpi=200, bbox_inches="tight")
            print(f"Saved: {path}")

        plt.close(fig)

    except (OSError, ValueError, KeyError) as exc:
        parser.exit(1, f"Chart generation failed: {exc}\n")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())