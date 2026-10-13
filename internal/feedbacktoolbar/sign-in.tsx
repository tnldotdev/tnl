export function SignInLink({ path }: { path: string }) {
  return (
    <a
      class="account-link"
      href={"/__tnl/team/login?return=" + encodeURIComponent(path)}
      target="_blank"
      rel="noopener noreferrer"
    >
      [ sign in ]
    </a>
  );
}
