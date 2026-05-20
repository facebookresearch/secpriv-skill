// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

// React render path — JSX auto-escapes interpolated text, not XSS.
import React from "react";

type Props = { name: string; bio: string };

export function Profile({ name, bio }: Props) {
  // {name} and {bio} are escaped by React; even <script>alert(1)</script>
  // renders as text. No dangerouslySetInnerHTML used.
  return (
    <section>
      <h1>Hello, {name}</h1>
      <p>{bio}</p>
    </section>
  );
}
