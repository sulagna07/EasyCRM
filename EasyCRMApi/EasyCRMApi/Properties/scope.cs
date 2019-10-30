private readonly IServiceProvider _provider;
private readonly Dictionary<string, Type> _workerList1=new Dictionary<string, Type>();
private delegate RtmsResp<dynamic> ExecuteOperationDelegate<T>(T x);
public WorkerMonitor(IServiceProvider provider)
{
	_provider = provider;
	_workerList1.Add("1", typeof(ICommonWorker));
}

public dynamic SelectWorker(RtmRequest<dynamic> req)
{
	using (var scope = _provider.CreateScope())
	{
		var scopedProcessingService =
			scope.ServiceProvider
				.GetRequiredService(_workerList1["1"]);
		var dlgate = Delegate.CreateDelegate(typeof(ExecuteOperationDelegate<RtmRequest<dynamic>>), scopedProcessingService, "ExecuteOperation");
		return dlgate.DynamicInvoke(req);
	}
	/*var reqservice=_provider.GetRequiredService(_workerList1["1"]);
	var dlgate = Delegate.CreateDelegate(typeof(ExecuteOperationDelegate<RtmRequest<dynamic>>), reqservice, "ExecuteOperation");
	return dlgate.DynamicInvoke(req);*/
}

=======================================
services.AddScoped<ICommonWorker, CommonWorker>();
=======================================
public interface IWorkerMonitor
{
	dynamic SelectWorker(RtmRequest<dynamic> req);
}
========================================



