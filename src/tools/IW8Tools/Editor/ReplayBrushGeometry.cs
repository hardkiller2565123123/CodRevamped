using System.Windows.Media.Media3D;

namespace CodRevamped.IW8Tools;

// Authored convex brush geometry. The same topology drives the editor preview,
// OBJ source, IW8 render surfaces and MWCOLL02 Havok-baker input.
internal static class ReplayBrushGeometry
{
    internal sealed record Mesh(Point3D[] Points, int[][] Faces);

    internal static Mesh Build(string kind, double x, double y, double z,
        double width, double length, double height, double yawDegrees)
    {
        if (width < .125 || length < .125 || height < .125 ||
            !double.IsFinite(x) || !double.IsFinite(y) || !double.IsFinite(z) ||
            !double.IsFinite(width) || !double.IsFinite(length) || !double.IsFinite(height) ||
            !double.IsFinite(yawDegrees))
            throw new InvalidOperationException("Invalid brush coordinates or dimensions.");
        double a = width / 2, b = length / 2, c = height / 2;
        var local = new List<Point3D>();
        var faces = new List<int[]>();
        switch (kind)
        {
            case "box":
                local.AddRange([
                    new(-a,-b,-c),new(a,-b,-c),new(a,b,-c),new(-a,b,-c),
                    new(-a,-b,c),new(a,-b,c),new(a,b,c),new(-a,b,c)
                ]);
                faces.AddRange([[0,1,2,3],[4,7,6,5],[0,4,5,1],
                                [3,2,6,7],[0,3,7,4],[1,5,6,2]]);
                break;
            case "ramp":
                // Triangular prism, not a paper-thin slanted plane. Native
                // collision sees a valid closed convex hull with six vertices.
                local.AddRange([
                    new(-a,-b,-c),new(a,-b,-c),new(a,b,-c),new(-a,b,-c),
                    new(-a,b,c),new(a,b,c)
                ]);
                faces.AddRange([[0,1,2,3],[3,2,5,4],[0,3,4],
                                [1,5,2],[0,4,5,1]]);
                break;
            case "cylinder":
                const int sides = 12;
                for (int j=0;j<2;j++)
                    for (int i=0;i<sides;i++)
                    {
                        var angle = (2*Math.PI*i)/sides;
                        local.Add(new Point3D(a*Math.Cos(angle),b*Math.Sin(angle),j==0?-c:c));
                    }
                faces.Add(Enumerable.Range(0,sides).ToArray());
                faces.Add(Enumerable.Range(sides,sides).ToArray());
                for (int i=0;i<sides;i++)
                    faces.Add([i,(i+1)%sides,(i+1)%sides+sides,i+sides]);
                break;
            default: throw new InvalidOperationException("Unknown brush shape: "+kind);
        }
        var angleYaw = yawDegrees * Math.PI / 180;
        var co = Math.Cos(angleYaw); var si = Math.Sin(angleYaw);
        Point3D[] points = local.Select(p => new Point3D(
            x+p.X*co-p.Y*si,y+p.X*si+p.Y*co,z+p.Z)).ToArray();
        // Correct windings from the polygon centroid, including the ramp slope.
        var center = new Point3D(points.Average(p=>p.X),points.Average(p=>p.Y),points.Average(p=>p.Z));
        foreach (var face in faces)
        {
            var n = Vector3D.CrossProduct(points[face[1]]-points[face[0]],
                points[face[2]]-points[face[0]]);
            var origin = points[face[0]];
            var towardsCenter = center - origin;
            if (Vector3D.DotProduct(n,towardsCenter)>0) Array.Reverse(face);
            if (n.LengthSquared < .000001)
                throw new InvalidOperationException("Degenerate brush polygon detected.");
        }
        return new Mesh(points,faces.ToArray());
    }

    internal static Vector3D Normal(Point3D[] points,int[] face)
    {
        var normal=Vector3D.CrossProduct(points[face[1]]-points[face[0]],
                                         points[face[2]]-points[face[0]]);
        normal.Normalize();return normal;
    }

    // Uses the tangent->binormal->normal quaternion decomposition and Dec3n
    // (10/10/9 + handedness + largest component) from MW120R replay_mesh_math.py.
    internal static uint PackNormal(Vector3D n, Vector3D tangent)
    {
        n.Normalize();
        tangent -= n * Vector3D.DotProduct(tangent,n);
        if (tangent.LengthSquared < 1e-10)
            tangent=Vector3D.CrossProduct(Math.Abs(n.Z)<.9?new Vector3D(0,0,1):new Vector3D(0,1,0),n);
        tangent.Normalize();
        var binormal=Vector3D.CrossProduct(n,tangent);binormal.Normalize();
        var m=new[,]{{tangent.X,binormal.X,n.X},{tangent.Y,binormal.Y,n.Y},
                      {tangent.Z,binormal.Z,n.Z}};
        var q=new double[4];
        var trace=m[0,0]+m[1,1]+m[2,2];
        if(trace>0)
        {
            var s=Math.Sqrt(trace+1)*2;
            q[0]=(m[2,1]-m[1,2])/s;q[1]=(m[0,2]-m[2,0])/s;
            q[2]=(m[1,0]-m[0,1])/s;q[3]=s/4;
        }
        else
        {
            var i=Enumerable.Range(0,3).MaxBy(i=>m[i,i]);
            var j=(i+1)%3;var k=(i+2)%3;
            var s=Math.Sqrt(1+m[i,i]-m[j,j]-m[k,k])*2;
            q[i]=s/4;q[j]=(m[j,i]+m[i,j])/s;q[k]=(m[k,i]+m[i,k])/s;
            q[3]=(m[k,j]-m[j,k])/s;
        }
        var major=Enumerable.Range(0,4).OrderBy(i=>Math.Abs(q[i])).ThenBy(i=>i).Last();
        var scale=Math.Sqrt(2)*(q[major]>=0?1:-1);
        var remaining=Enumerable.Range(0,4).Where(i=>i!=major).Select(i=>q[i]*scale).ToArray();
        uint Q(double v,int bits)=>(uint)Math.Clamp((int)((v+1)*((1<<bits)-1)/2),0,(1<<bits)-1);
        return Q(remaining[0],10)|(Q(remaining[1],10)<<10)|(Q(remaining[2],9)<<20)|
               ((uint)major<<30);
    }
}
