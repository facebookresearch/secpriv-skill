# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""Django POST endpoint protected by @csrf_protect."""

from django.http import JsonResponse
from django.views.decorators.csrf import csrf_protect


@csrf_protect
def update_email(request):
    # @csrf_protect rejects requests without a valid CSRF token,
    # so cross-site forgery is prevented.
    email = request.POST["email"]
    _save(email)
    return JsonResponse({"updated": True})


def _save(e):
    pass
