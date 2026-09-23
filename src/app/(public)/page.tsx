import { Dashboard } from "@/components/dashboard/dashboard";
import { getPublicKevDashboardData } from "@/features/kev/queries";

export default async function Page() {
  let kev = null;
  let kevError = false;
  try {
    kev = await getPublicKevDashboardData();
  } catch {
    kevError = true;
  }
  return <Dashboard kev={kev} kevError={kevError} />;
}
