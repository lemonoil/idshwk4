@load base/frameworks/sumstats

event http_reply (c: connection, version: string, code: count, reason: string)
{

    SumStats::observe("all_response",SumStats::Key($host=c$id$orig_h),SumStats::Observation($num=1));
    if(code==404)
    {
        SumStats::observe("bad_response",SumStats::Key($host=c$id$orig_h),SumStats::Observation($num=1));
        SumStats::observe("bad_url",SumStats::Key($host=c$id$orig_h),SumStats::Observation($str=c$http$uri));
    }
}

event zeek_init()
{

    local r1 = SumStats::Reducer($stream="all_response", $apply=set(SumStats::SUM));
    local r2 = SumStats::Reducer($stream="bad_response", $apply=set(SumStats::SUM));
    local r3 = SumStats::Reducer($stream="bad_url", $apply=set(SumStats::UNIQUE));

    SumStats::create([$name = "result_output",
                    $epoch = 10min,
                    $reducers = set(r1,r2,r3),
                    $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) =
                    {
                    local all_res=result["all_response"];
                    local bad_res=result["bad_response"];
                    local bad_u=result["bad_url"];
                    if(bad_res$sum>2&&(bad_res$sum/all_res$sum)>0.2)
                    {
                        if((bad_u$unique/bad_res$sum)>0.5)
                        {
                            print fmt("%s is a scanner with %d scan attemps on %d urls", key$host,bad_res$sum,bad_u$unique);
                        }
                    }

                    
                    }]);
}
