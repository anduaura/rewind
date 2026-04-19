class Rewind < Formula
  desc "Deterministic replay of distributed system incidents"
  homepage "https://github.com/anduaura/rewind"
  version "0.1.0"
  license "Apache-2.0"

  on_linux do
    on_intel do
      url "https://github.com/anduaura/rewind/releases/download/v#{version}/rewind-linux-x86_64"
      sha256 "PLACEHOLDER_SHA256_AMD64"
    end

    on_arm do
      url "https://github.com/anduaura/rewind/releases/download/v#{version}/rewind-linux-arm64"
      sha256 "PLACEHOLDER_SHA256_ARM64"
    end
  end

  def install
    bin.install stable.url.split("/").last => "rewind"
  end

  test do
    assert_match "rewind", shell_output("#{bin}/rewind --help")
  end
end
