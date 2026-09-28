# NixOS VM test of the NixOS and home-manager modules: the host and the user
# alice each have their own mnemonic (SPEC.md section 10).
{
  pkgs,
  self,
  home-manager,
}:

pkgs.testers.runNixOSTest {
  name = "bixfuse-modules";

  nodes.machine = {
    imports = [
      self.nixosModules.default
      home-manager.nixosModules.home-manager
    ];

    # The mnemonic of the host. A real host must keep it out of the Nix store.
    environment.etc.mnemonic.text = "legal winner thank year wave sausage worth useful legal winner thank yellow\n";

    services.openssh.enable = true;
    environment.systemPackages = [
      self.packages.${pkgs.stdenv.hostPlatform.system}.default
      pkgs.git
    ];

    bixfuse = {
      programs.enable = true;
      secrets = {
        drone-user = {
          type.bip39 = {
            language = "english";
            words = 12;
            index = 0;
          };
          owner = "alice";
          group = "users";
          mode = "0440";
        };
        token = {
          derivation = "hex/32/0";
          path = "/var/lib/token";
        };
      };
    };

    users.users.alice.isNormalUser = true;
    home-manager.users.alice = {
      imports = [ self.homeManagerModules.default ];
      home.stateVersion = "25.05";
      programs.git.enable = true;
      bixfuse = {
        programs.enable = true;
        user = {
          name = "Alice Liddell";
          email = "alice@example.org";
        };
        secrets.age-recipient.type.age.public = true;
      };
    };
  };

  testScript = ''
    import shlex

    def alice(command):
        return machine.succeed("su - alice -c " + shlex.quote(command))

    machine.wait_for_unit("multi-user.target")

    with subtest("host secrets"):
        # From bipsea 4.0.0 for the mnemonic of the host.
        assert machine.succeed("cat /run/bixfuse/drone-user") == "weird hair hip place rail airport twin immense stomach later push carpet\n"
        assert machine.succeed("stat -L -c '%a %U %G' /run/bixfuse/drone-user").strip() == "440 alice users"
        assert alice("cat /run/bixfuse/drone-user").startswith("weird hair")
        assert machine.succeed("cat /var/lib/token") == "2561c4f218d4d9cdf4c374dbf0b56169f6a3db34d0cf6ec4e75beec2e45dc5f4\n"
        assert machine.succeed("readlink /var/lib/token").strip() == "/run/bixfuse/token"
        assert machine.succeed("stat -L -c '%a %U' /var/lib/token").strip() == "400 root"
        machine.fail("su - alice -c 'cat /var/lib/token'")
        assert " /run/bixfuse.d ramfs " in machine.succeed("cat /proc/mounts")

    with subtest("host keys"):
        machine.wait_for_unit("sshd.service")
        machine.fail("systemctl cat sshd-keygen.service")
        cat = "bixfuse cat --mnemonic-file /etc/mnemonic "
        ed25519 = machine.succeed(cat + ".ssh/ed25519/0/id_ed25519.pub").strip()
        assert machine.succeed("cat /etc/ssh/ssh_host_ed25519_key.pub").strip() == ed25519
        assert machine.succeed("stat -c '%a' /etc/ssh/ssh_host_ed25519_key /etc/ssh/ssh_host_rsa_key").split() == ["600", "600"]
        scanned = machine.succeed("ssh-keyscan -t ed25519 localhost 2>/dev/null")
        assert ed25519.split()[1] in scanned, scanned
        rsa = machine.succeed(cat + ".ssh/rsa/4096/0/id_rsa.pub").strip()
        assert rsa.split()[1] in machine.succeed("ssh-keyscan -t rsa localhost 2>/dev/null")

    with subtest("activation refuses to replace a different host key"):
        machine.succeed("cp /etc/ssh/ssh_host_ed25519_key.pub /tmp/key.pub")
        machine.succeed("echo other > /etc/ssh/ssh_host_ed25519_key.pub")
        out = machine.fail("/run/current-system/activate 2>&1")
        assert "/etc/ssh/ssh_host_ed25519_key.pub exists with a different key" in out, out
        assert machine.succeed("cat /etc/ssh/ssh_host_ed25519_key.pub") == "other\n"
        machine.succeed("rm /etc/ssh/ssh_host_ed25519_key.pub")
        machine.succeed("/run/current-system/activate")
        machine.succeed("cmp /etc/ssh/ssh_host_ed25519_key.pub /tmp/key.pub")

    with subtest("user: SSH key and git identity"):
        # Home Manager ran at boot without the mnemonic of alice, so it failed.
        alice("mkdir -p ~/.config/bixfuse")
        alice("echo 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about' > ~/.config/bixfuse/mnemonic")
        machine.succeed("systemctl restart home-manager-alice.service")
        # From Python cryptography for the mnemonic of alice (SPEC.md section 5.3).
        assert alice("cat ~/.ssh/id_ed25519.pub") == "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINcZp5MpnnfHtWuKtCgQIpI0CQQPbSVnpvgZO9BvDq/l\n"
        assert alice("ssh-keygen -y -f ~/.ssh/id_ed25519") == alice("cat ~/.ssh/id_ed25519.pub")
        assert alice("stat -c '%a' ~/.ssh ~/.ssh/id_ed25519 ~/.ssh/id_ed25519.pub").split() == ["700", "600", "644"]
        assert alice("git config user.name") == "Alice Liddell\n"
        assert alice("git config user.email") == "alice@example.org\n"
        # The host key and the user key come from different mnemonics.
        assert alice("cat ~/.ssh/id_ed25519.pub").strip() != ed25519

    with subtest("user secrets"):
        machine.succeed("loginctl enable-linger alice")
        machine.wait_for_unit("user@1000.service")
        try:
            machine.wait_for_unit("bixfuse-secrets.service", "alice")
        except Exception:
            print(machine.execute("journalctl --no-pager -n 50 _UID=1000")[1])
            raise
        # From age-keygen 1.3.2 for the mnemonic of alice.
        assert alice("cat /run/user/1000/bixfuse/age-recipient") == "age1e240cs8tjjvwus4jtfpfn4v6pu5r3gfc2jv0psm6l6ptzpzsvvgsyn4fcd\n"
        assert alice("stat -L -c '%a %U' /run/user/1000/bixfuse/age-recipient").strip() == "400 alice"
  '';
}
