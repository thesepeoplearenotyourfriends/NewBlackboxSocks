package top.niunaijun.webviewprobe;

import android.app.job.JobParameters;
import android.app.job.JobService;
import android.util.Log;

public final class ProbeJobService extends JobService {
    @Override
    public boolean onStartJob(JobParameters params) {
        Log.i("WVPROBE", "jobservice START local-only");
        return false;
    }

    @Override
    public boolean onStopJob(JobParameters params) {
        Log.i("WVPROBE", "jobservice STOP");
        return false;
    }
}
