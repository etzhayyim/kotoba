class Kotoba < Formula
  desc "Content-addressed distributed Datalog database with native CACAO auth"
  homepage "https://github.com/etzhayyim/kotoba"
  url "https://github.com/etzhayyim/kotoba/archive/refs/tags/v0.1.0.tar.gz"
  sha256 "cdf1099d970aa6e5be0e88099fc58bcefea58cadec63392863c3b7538a883655"
  license "Apache-2.0"
  head "https://github.com/etzhayyim/kotoba.git", branch: "main"

  depends_on "rust" => :build

  def install
    # The `kotoba` binary lives in the kotoba-cli crate inside the workspace.
    # `--locked` is enforced via std_cargo_args.
    system "cargo", "install",
           *std_cargo_args(path: "crates/kotoba-cli"),
           "--bin", "kotoba"
  end

  test do
    # `kotoba --help` exits 0 and lists subcommands.  Cheap smoke test that
    # the binary is on PATH and links against its deps correctly.
    assert_match "kotoba", shell_output("#{bin}/kotoba --help")

    # `kotoba did-derive` is a pure-computation subcommand — no server, no
    # IPFS, no keychain — perfect for CI smoke verification.
    seed = "0000000000000000000000000000000000000000000000000000000000000001"
    did_out = shell_output("#{bin}/kotoba did-derive #{seed}")
    assert_match "did:key:z", did_out
  end
end
