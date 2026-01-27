# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

"""
Unit tests for the Celery app teardown handler.

These tests verify that the teardown function properly handles
the Flask application context to avoid "Working outside of application context"
errors during scheduled report execution.
"""

from typing import Any
from unittest.mock import MagicMock


def create_teardown_function(
    flask_app: MagicMock,
    db: MagicMock,
    has_app_context_func: Any,
) -> Any:
    """
    Create a teardown function with mocked dependencies.

    This replicates the logic from superset/tasks/celery_app.py without
    needing to import the module (which triggers Flask app creation).
    """

    def teardown(
        retval: Any,
        *args: Any,
        **kwargs: Any,
    ) -> None:
        if flask_app.config.get("SQLALCHEMY_COMMIT_ON_TEARDOWN"):
            if not isinstance(retval, Exception):
                db.session.commit()

        if not flask_app.config.get("CELERY_ALWAYS_EAGER"):
            if has_app_context_func():
                db.session.remove()

    return teardown


def test_teardown_with_app_context() -> None:
    """
    Test that teardown removes session when app context is available.
    """
    mock_flask_app = MagicMock()
    mock_flask_app.config.get.side_effect = lambda key: {
        "SQLALCHEMY_COMMIT_ON_TEARDOWN": False,
        "CELERY_ALWAYS_EAGER": False,
    }.get(key)

    mock_db = MagicMock()
    teardown = create_teardown_function(mock_flask_app, mock_db, lambda: True)

    teardown(retval=None)
    mock_db.session.remove.assert_called_once()


def test_teardown_without_app_context() -> None:
    """
    Test that teardown skips session removal when no app context is available.
    This prevents "Working outside of application context" errors.
    """
    mock_flask_app = MagicMock()
    mock_flask_app.config.get.side_effect = lambda key: {
        "SQLALCHEMY_COMMIT_ON_TEARDOWN": False,
        "CELERY_ALWAYS_EAGER": False,
    }.get(key)

    mock_db = MagicMock()
    teardown = create_teardown_function(mock_flask_app, mock_db, lambda: False)

    teardown(retval=None)
    # Should NOT call db.session.remove() when no app context
    mock_db.session.remove.assert_not_called()


def test_teardown_with_commit_on_success() -> None:
    """
    Test that teardown commits session on success when configured.
    """
    mock_flask_app = MagicMock()
    mock_flask_app.config.get.side_effect = lambda key: {
        "SQLALCHEMY_COMMIT_ON_TEARDOWN": True,
        "CELERY_ALWAYS_EAGER": False,
    }.get(key)

    mock_db = MagicMock()
    teardown = create_teardown_function(mock_flask_app, mock_db, lambda: True)

    teardown(retval="success")
    mock_db.session.commit.assert_called_once()
    mock_db.session.remove.assert_called_once()


def test_teardown_with_exception() -> None:
    """
    Test that teardown does not commit when task returns an exception.
    """
    mock_flask_app = MagicMock()
    mock_flask_app.config.get.side_effect = lambda key: {
        "SQLALCHEMY_COMMIT_ON_TEARDOWN": True,
        "CELERY_ALWAYS_EAGER": False,
    }.get(key)

    mock_db = MagicMock()
    teardown = create_teardown_function(mock_flask_app, mock_db, lambda: True)

    exception = Exception("Task failed")
    teardown(retval=exception)
    # Should NOT commit when retval is an exception
    mock_db.session.commit.assert_not_called()
    mock_db.session.remove.assert_called_once()


def test_teardown_with_eager_mode() -> None:
    """
    Test that teardown skips session removal when in eager mode.
    """
    mock_flask_app = MagicMock()
    mock_flask_app.config.get.side_effect = lambda key: {
        "SQLALCHEMY_COMMIT_ON_TEARDOWN": False,
        "CELERY_ALWAYS_EAGER": True,
    }.get(key)

    mock_db = MagicMock()
    teardown = create_teardown_function(mock_flask_app, mock_db, lambda: True)

    teardown(retval=None)
    # Should NOT call db.session.remove() in eager mode
    mock_db.session.remove.assert_not_called()
