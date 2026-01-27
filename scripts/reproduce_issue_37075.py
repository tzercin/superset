#!/usr/bin/env python
"""
Script to reproduce GitHub issue #37075:
"Working outside of application context" error in Celery teardown.

Run this BEFORE the fix to see the error, and AFTER to verify it's fixed.

Usage:
    python scripts/reproduce_issue_37075.py
"""

from superset import create_app
from superset.extensions import db

# Create the Flask app
flask_app = create_app()


def simulate_teardown_without_context():
    """
    Simulates what happens when the Celery task_postrun signal fires
    outside of an app context (the bug condition).
    """
    print("Simulating teardown outside of app context...")
    print("-" * 60)

    # This is what the OLD code did - call db.session.remove() directly
    # without checking for app context
    try:
        print("OLD behavior (without has_app_context check):")
        print("  Calling db.session.remove() outside app context...")
        db.session.remove()
        print("  ✓ No error (unexpected)")
    except RuntimeError as e:
        print(f"  ✗ RuntimeError: {e}")
        print("  This is the bug that issue #37075 reports!")

    print()

    # This is what the NEW code does - check for app context first
    from flask import has_app_context

    print("NEW behavior (with has_app_context check):")
    if has_app_context():
        print("  App context exists, calling db.session.remove()...")
        db.session.remove()
    else:
        print("  ✓ No app context, skipping db.session.remove()")
        print("  This is the fix - no error!")


def simulate_teardown_with_context():
    """
    Simulates the normal case when teardown happens within an app context.
    """
    print()
    print("Simulating teardown INSIDE app context...")
    print("-" * 60)

    with flask_app.app_context():
        from flask import has_app_context

        print("Inside app context:")
        if has_app_context():
            print("  App context exists, calling db.session.remove()...")
            db.session.remove()
            print("  ✓ Success!")
        else:
            print("  No app context (unexpected)")


if __name__ == "__main__":
    print("=" * 60)
    print("Reproducing GitHub Issue #37075")
    print("https://github.com/apache/superset/issues/37075")
    print("=" * 60)
    print()

    simulate_teardown_without_context()
    simulate_teardown_with_context()

    print()
    print("=" * 60)
    print("Done!")
