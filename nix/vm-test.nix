# NixOS VM test: a normal user mounts bixfuse and reads the files.
{ pkgs, bixfuse }:

pkgs.testers.runNixOSTest {
  name = "bixfuse";

  nodes.machine = {
    # A normal user can mount only with the setuid fusermount3 wrapper.
    programs.fuse.enable = true;
    users.users.alice.isNormalUser = true;
    environment.systemPackages = [
      bixfuse
      pkgs.age
      pkgs.gnupg
      pkgs.openssh
    ];
  };

  testScript = ''
    import shlex
    from datetime import timedelta

    def alice(command):
        return machine.succeed("su - alice -c " + shlex.quote(command))

    def alice_fails(command):
        machine.fail("su - alice -c " + shlex.quote(command))

    machine.wait_for_unit("multi-user.target")
    mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    hex_32_0 = "e477d4694160a384b28ee2f72b54edcf0822fd6e1ee1780447455cdbed8f8c45\n"
    alice(f"echo '{mnemonic}' > mnemonic")
    alice("mkdir mnt mnt2")
    # The mnemonic comes from ./mnemonic, a default file. The test driver's
    # standard input is not a terminal and does not end, so redirect it.
    alice("setsid -f bixfuse --gpg-user-id 'Test <test@example.org>' mnt < /dev/null > bixfuse.log 2>&1")
    # Only alice can stat the mount point: the mount does not use allow_other.
    mounted = "su - alice -c 'mountpoint -q mnt'"
    try:
        machine.wait_until_succeeds(mounted, timeout=timedelta(seconds=60))
    except Exception:
        print(machine.execute("cat /home/alice/bixfuse.log; ps -ef | grep -e bixfuse -e fusermount")[1])
        raise

    with subtest("the examples of the first request"):
        assert alice("cat mnt/bip39/english/12/0") == "prosper short ramp prepare exchange stove life snack client enough purpose fold\n"
        assert alice("cat mnt/hex/32/0") == hex_32_0

    with subtest("mnemonic sources"):
        alice(f"echo '{mnemonic}' | setsid -f bixfuse mnt2 > bixfuse2.log 2>&1")
        machine.wait_until_succeeds("su - alice -c 'mountpoint -q mnt2'", timeout=timedelta(seconds=60))
        assert alice("cat mnt2/hex/32/0") == hex_32_0
        alice("fusermount3 -u mnt2")
        machine.wait_until_fails("su - alice -c 'mountpoint -q mnt2'")

        both = machine.fail("su - alice -c " + shlex.quote(f"echo '{mnemonic}' | bixfuse --mnemonic-file mnemonic mnt2 2>&1"))
        assert "use only one" in both, both
        none = machine.fail("su - alice -c " + shlex.quote("cd /tmp && bixfuse /home/alice/mnt2 < /dev/null 2>&1"))
        assert "/etc/mnemonic, /home/alice/.config/bixfuse/mnemonic, ./mnemonic, ./mnemonic.txt" in none, none

    with subtest("listings"):
        # ls hides the hidden directories of the encodings; ls -A shows them.
        assert alice("ls mnt").split() == ["base64", "base85", "bip39", "dice", "hex", "nostr", "rsa", "wif", "xprv"]
        assert sorted(alice("ls -A mnt").split()) == [
            ".age", ".gnupg", ".ssh", "base64", "base85", "bip39", "dice", "hex", "nostr", "rsa", "wif", "xprv",
        ]
        assert sorted(alice("ls mnt/rsa/2048/0").split()) == ["0", "1", "2", "private.pem"]
        assert sorted(alice("ls -A mnt/.ssh").split()) == [
            "ed25519", "id_ed25519", "id_ed25519.pub", "id_rsa", "id_rsa.pub", "rsa",
        ]
        assert sorted(alice("ls -A mnt/.age").split()) == [
            "mlkem768x25519", "private-pq.age", "private.age", "public-pq.age", "public.age", "x25519",
        ]
        assert sorted(alice("ls -A mnt/.gnupg").split()) == ["public.asc", "rsa", "secret.asc"]

    with subtest("every file kind"):
        for path in [
            "bip39/czech/24/3", "wif/0", "xprv/0", "base64/20/0", "base85/80/0",
            "dice/6/10/0", "nostr/1/1", "rsa/2048/0/1/private.pem",
            ".ssh/ed25519/1/id_ed25519.pub", ".ssh/rsa/2048/0/2/id_rsa.pub",
            ".age/x25519/1/public.age", ".age/mlkem768x25519/1/public.age", ".gnupg/rsa/2048/0/public.asc",
        ]:
            text = alice(f"cat mnt/{path}")
            assert len(text) > 1 and text.endswith("\n"), path

    with subtest("flat defaults are index 0"):
        assert alice("cat mnt/.ssh/id_ed25519") == alice("cat mnt/.ssh/ed25519/0/id_ed25519")
        assert alice("cat mnt/.age/public.age") == alice("cat mnt/.age/x25519/0/public.age")
        assert alice("cat mnt/.age/public-pq.age") == alice("cat mnt/.age/mlkem768x25519/0/public.age")
        assert alice("cat mnt/.ssh/id_rsa.pub") == alice("cat mnt/.ssh/rsa/4096/0/id_rsa.pub")

    with subtest("attributes"):
        assert alice("stat -c '%a %U %s' mnt/hex/32/0").strip() == "400 alice 65"
        assert alice("stat -c '%a %F' mnt/hex/32").strip() == "500 directory"

    with subtest("reference tools read the key files"):
        assert alice("age-keygen -y mnt/.age/private.age") == alice("cat mnt/.age/public.age")
        assert alice("age-keygen -y mnt/.age/private-pq.age") == alice("cat mnt/.age/public-pq.age")
        roundtrip = "echo bixfuse | age -r \"$(cat mnt/.age/public-pq.age)\" | age -d -i mnt/.age/private-pq.age"
        assert alice(roundtrip) == "bixfuse\n"
        assert alice("ssh-keygen -y -f mnt/.ssh/id_ed25519") == alice("cat mnt/.ssh/id_ed25519.pub")
        assert alice("ssh-keygen -y -f mnt/.ssh/rsa/2048/0/id_rsa") == alice("cat mnt/.ssh/rsa/2048/0/id_rsa.pub")
        assert alice("ssh-keygen -y -f mnt/rsa/2048/0/private.pem") == alice("cat mnt/.ssh/rsa/2048/0/id_rsa.pub")
        alice("gpg --batch --import mnt/.gnupg/rsa/2048/0/secret.asc")
        assert "fpr:::::::::ECC1557BE1B91255FAC1BB370ABFE55998DF2870:" in alice("gpg --batch --with-colons --list-secret-keys")

    with subtest("missing paths, writes, and other users fail"):
        alice_fails("cat mnt/hex/base64/32/0")
        alice_fails("cat mnt/hex/32/007")
        alice_fails("cat mnt/age/x25519/0/private.age")
        alice_fails("cat mnt/rsa/2048/0/openssh-key-v1")
        alice_fails("touch mnt/hex/32/new")
        machine.fail("cat /home/alice/mnt/hex/32/0")

    with subtest("SIGTERM unmounts"):
        machine.succeed("pkill -TERM -x bixfuse")
        machine.wait_until_fails(mounted)
        assert "error" not in alice("cat bixfuse.log").lower()
  '';
}
