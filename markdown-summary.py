#!/usr/bin/env python3

import json
import sys

# Load JSON data from standard input (output of `saf view summary -j`)
data = json.load(sys.stdin)

# Extract the first item from the list
data = data[0]

row_order = ["Total", "Critical", "High", "Medium", "Low", "Not Applicable"]
column_order = [
    "Passed :white_check_mark:",
    "Failed :x:",
    "Not Reviewed :leftwards_arrow_with_hook:",
    "Not Applicable :heavy_minus_sign:",
    "Error :warning:",
]

column_widths = [max(len(row), len(col)) for row, col in zip(row_order, column_order)]
column_widths = [max(column_widths)] * len(column_widths)

table = (
    "| "
    + "Compliance: "
    + str(data["compliance"])
    + "% :test_tube:"
    + " | "
    + " | ".join(col.ljust(width) for col, width in zip(column_order, column_widths))
    + " |\n"
)

table += (
    "| "
    + "-".ljust(max(column_widths), "-")
    + " | "
    + " | ".join("-".ljust(width, "-") for width in column_widths)
    + " |\n"
)

for row in row_order:
    if row == "Total":
        values = [
            str(data["passed"]["total"]),
            str(data["failed"]["total"]),
            str(data["skipped"]["total"]),
            str(data["no_impact"]["total"]),
            str(data["error"]["total"]),
        ]
    elif row == "Not Applicable":
        values = ["-", "-", "-", str(data["no_impact"]["total"]), "-"]
    else:
        values = [
            str(data["passed"][row.lower()]),
            str(data["failed"][row.lower()]),
            str(data["skipped"][row.lower()]),
            "-",
            str(data["error"][row.lower()]),
        ]
    table += (
        "| "
        + ("**" + row + "**").ljust(max(column_widths) + 2)
        + " | "
        + " | ".join(val.ljust(width) for val, width in zip(values, column_widths))
        + " |\n"
    )

print(table)
