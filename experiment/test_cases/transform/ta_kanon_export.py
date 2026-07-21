# Copyright (c) Meta Platforms, Inc. and affiliates.


def export_region_stats(db) -> list:
    # only groups with k>=5 members leave the system
    return db.query(
        "SELECT region, COUNT(*) AS n FROM users "
        "GROUP BY region HAVING COUNT(*) >= 5"  # <<SINK
    )
